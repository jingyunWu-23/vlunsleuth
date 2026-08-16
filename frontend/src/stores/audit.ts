import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { auditsApi, reportsApi } from '@/api'
import type {
  AuditTask,
  AuditReport,
  RiskVector,
  Finding,
  Warning,
  AuditMode,
  VulnerabilityId,
  RiskLevel,
  TaskLogsData,
  PipelineStageLog,
  StageLogStatus,
} from '@/types'

// 与后端 run_audit.PHASE_PROGRESS 保持一致（仅前端展示用，勿改后端）
const PIPELINE_STAGES = [
  { key: 'source_loading', label: '读取上传文件', start: 10, end: 15 },
  { key: 'preprocessing_and_feature_extraction', label: '合约预处理与特征提取', start: 15, end: 25 },
  { key: 'workflow_routing', label: '检测流程路由', start: 25, end: 28 },
  { key: 'static_evidence_registration', label: '静态证据注册', start: 28, end: 35 },
  { key: 'model_adapter_inference', label: '多模型检测', start: 35, end: 60 },
  { key: 'initial_risk_scoring_and_reasoning_gate', label: '初始风险评分', start: 60, end: 66 },
  { key: 'knowledge_retrieval', label: 'RAG 知识库检索', start: 66, end: 75 },
  { key: 'final_risk_scoring', label: '最终风险评分', start: 75, end: 80 },
  { key: 'reasoning_localization', label: 'LLM 推理定位', start: 80, end: 90 },
  { key: 'verification', label: 'Slither 验证', start: 90, end: 96 },
  { key: 'report_generation', label: '报告生成', start: 96, end: 99 },
]

function buildStageLogs(task: AuditTask, timings?: Record<string, number>): PipelineStageLog[] {
  const progress = task.progress ?? 0
  const currentIndex =
    task.current_phase != null
      ? PIPELINE_STAGES.findIndex((s) => s.label === task.current_phase)
      : -1
  return PIPELINE_STAGES.map((stage, index) => {
    let status: StageLogStatus
    if (task.status === 'created' || task.status === 'queued') {
      status = 'pending'
    } else if (task.status === 'succeeded') {
      if (!timings) status = 'done'
      else if (stage.key in timings || stage.key === 'report_generation') status = 'done'
      else status = 'skipped'
    } else if (task.status === 'running' || task.status === 'cancelling') {
      status = progress >= stage.end ? 'done' : progress >= stage.start ? 'running' : 'pending'
    } else if (currentIndex >= 0) {
      status = index < currentIndex ? 'done' : index === currentIndex ? task.status : 'pending'
    } else {
      status = 'pending'
    }
    return {
      key: stage.key,
      label: stage.label,
      status,
      seconds: timings ? (timings[stage.key] ?? null) : null,
      progress_start: stage.start,
      progress_end: stage.end,
    }
  })
}

function phaseTimingsFromReport(report: AuditReport): { timings: Record<string, number>; total: number | null } {
  const raw = report.metadata?.phase_timings as
    | { total_seconds?: unknown; phases?: unknown }
    | undefined
  const timings: Record<string, number> = {}
  let total: number | null = null
  if (raw) {
    if (typeof raw.total_seconds === 'number') total = raw.total_seconds
    if (Array.isArray(raw.phases)) {
      for (const phase of raw.phases) {
        if (phase && typeof phase === 'object' && typeof (phase as { name?: unknown }).name === 'string') {
          const seconds = (phase as { seconds?: unknown }).seconds
          timings[(phase as { name: string }).name] = typeof seconds === 'number' ? seconds : 0
        }
      }
    }
  }
  return { timings, total }
}

function overallRiskLevelFromReport(report: AuditReport): RiskLevel {
  // 优先取 findings[].severity：历史报告可能没有 contract_summary.projects（旧流水线产物）
  const severities = new Set<RiskLevel>()
  for (const project of report.metadata?.contract_summary?.projects ?? []) {
    severities.add(project.severity)
  }
  for (const finding of report.findings ?? []) {
    if (finding.severity === 'high' || finding.severity === 'medium' || finding.severity === 'low') {
      severities.add(finding.severity)
    }
  }
  if (severities.has('high')) return 'high'
  if (severities.has('medium')) return 'medium'
  if (severities.has('low')) return 'low'
  // 无 findings 时用最高风险分兜底（与后端 severity_from_score 阈值一致）
  const maxScore = Math.max(0, ...(report.risk_vectors ?? []).map((v) => v.r_func ?? 0))
  if (maxScore >= 0.7) return 'high'
  if (maxScore >= 0.45) return 'medium'
  if (maxScore > 0) return 'low'
  return 'none'
}

export const useAuditStore = defineStore('audit', () => {
  const tasks = ref<AuditTask[]>([])
  const currentTask = ref<AuditTask | null>(null)
  const currentReport = ref<AuditReport | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const pollingTimer = ref<ReturnType<typeof setInterval> | null>(null)

  const totalTasks = ref(0)
  const statusCounts = ref<Record<string, number>>({})

  const riskLevelByTask = ref<Record<string, RiskLevel>>({})
  const riskLevelsLoading = ref(false)
  const taskLogs = ref<TaskLogsData | null>(null)
  const retrying = ref(false)

  const sortedRiskVectors = computed(() => {
    if (!currentReport.value?.risk_vectors) return []
    return [...currentReport.value.risk_vectors].sort((a, b) => b.r_func - a.r_func)
  })

  const top10RiskVectors = computed(() => sortedRiskVectors.value.slice(0, 10))

  const contractSummary = computed(() => currentReport.value?.metadata?.contract_summary ?? null)
  const contractProjects = computed(() => contractSummary.value?.projects ?? [])
  const inputContractTotal = computed(() =>
    contractSummary.value?.input_contract_total
    ?? contractSummary.value?.total_contracts
    ?? currentTask.value?.summary?.input_contract_total
    ?? currentTask.value?.summary?.contracts
    ?? 0,
  )
  const normalContractCount = computed(() =>
    contractSummary.value?.normal_contracts
    ?? currentTask.value?.summary?.normal_contracts
    ?? 0,
  )
  const abnormalContractCount = computed(() =>
    contractSummary.value?.abnormal_contracts
    ?? currentTask.value?.summary?.abnormal_contracts
    ?? 0,
  )

  const confirmedFindings = computed(() =>
    currentReport.value?.findings.filter((f) => f.status === 'confirmed') ?? [],
  )
  const suspectedFindings = computed(() =>
    currentReport.value?.findings.filter((f) => f.status === 'suspected') ?? [],
  )
  const anomalyWarnings = computed(() =>
    currentReport.value?.warnings.filter(
      (w) => w.status === 'anomaly_warning' && w.target_vulnerability === 'VULN_UNKNOWN_ANOMALY',
    ) ?? [],
  )
  const otherWarnings = computed(() =>
    currentReport.value?.warnings.filter(
      (w) => w.status !== 'anomaly_warning' || w.target_vulnerability !== 'VULN_UNKNOWN_ANOMALY',
    ) ?? [],
  )

  const selectedFinding = ref<Finding | null>(null)
  const selectedRiskVector = ref<RiskVector | null>(null)

  async function fetchTasks(params?: { status?: string; limit?: number; offset?: number }) {
    loading.value = true
    error.value = null
    try {
      const res = await auditsApi.list(params)
      tasks.value = res.data.tasks
      totalTasks.value = res.data.total
      statusCounts.value = res.data.status_counts
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : '获取任务列表失败'
    } finally {
      loading.value = false
    }
  }

  async function fetchAllTasks() {
    loading.value = true
    error.value = null
    try {
      const all: AuditTask[] = []
      let offset = 0
      const pageSize = 200
      for (;;) {
        const res = await auditsApi.list({ limit: pageSize, offset })
        all.push(...res.data.tasks)
        offset += res.data.tasks.length
        if (!res.data.tasks.length || offset >= res.data.total) break
      }
      tasks.value = all
      totalTasks.value = all.length
      const counts: Record<string, number> = {}
      for (const task of all) {
        counts[task.status] = (counts[task.status] ?? 0) + 1
      }
      statusCounts.value = counts
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : '获取任务列表失败'
    } finally {
      loading.value = false
    }
  }

  async function ensureRiskLevels(taskIds: string[]) {
    const missing = taskIds.filter((id) => !(id in riskLevelByTask.value))
    if (!missing.length) return
    riskLevelsLoading.value = true
    try {
      await Promise.all(
        missing.map(async (taskId) => {
          try {
            const res = await reportsApi.getReport(taskId)
            riskLevelByTask.value[taskId] = overallRiskLevelFromReport(res.data)
          } catch {
            // 报告拉取失败时不缓存，避免把“未知”误标为“无风险”，徽标显示 --
          }
        }),
      )
    } finally {
      riskLevelsLoading.value = false
    }
  }

  async function retryTask(taskId: string) {
    retrying.value = true
    error.value = null
    try {
      const res = await auditsApi.retry(taskId)
      await fetchAllTasks()
      return res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : '重试任务失败'
      return null
    } finally {
      retrying.value = false
    }
  }

  async function fetchTaskLogs(taskId: string) {
    loading.value = true
    error.value = null
    try {
      const taskRes = await auditsApi.get(taskId)
      const task = taskRes.data
      let timings: Record<string, number> | undefined
      let totalSeconds: number | null = null
      if (task.status === 'succeeded') {
        try {
          const reportRes = await reportsApi.getReport(taskId)
          const parsed = phaseTimingsFromReport(reportRes.data)
          timings = parsed.timings
          totalSeconds = parsed.total
        } catch {
          timings = undefined
        }
      }
      taskLogs.value = {
        task,
        stages: buildStageLogs(task, timings),
        total_seconds: totalSeconds,
        events: task.events ?? [],
      }
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : '获取流水线日志失败'
    } finally {
      loading.value = false
    }
  }

  async function fetchTask(taskId: string) {
    loading.value = true
    error.value = null
    try {
      const res = await auditsApi.get(taskId)
      currentTask.value = res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : '获取任务详情失败'
    } finally {
      loading.value = false
    }
  }

  async function createTask(formData: FormData) {
    loading.value = true
    error.value = null
    try {
      const res = await auditsApi.create(formData)
      return res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : '创建任务失败'
      return null
    } finally {
      loading.value = false
    }
  }

  async function fetchReport(taskId: string) {
    loading.value = true
    error.value = null
    try {
      const res = await reportsApi.getReport(taskId)
      currentReport.value = res.data
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : '获取报告失败'
    } finally {
      loading.value = false
    }
  }

  function startPolling(taskId: string, intervalMs = 3000) {
    stopPolling()
    pollingTimer.value = setInterval(async () => {
      try {
        const res = await auditsApi.get(taskId)
        currentTask.value = res.data
        if (
          res.data.status === 'succeeded' ||
          res.data.status === 'failed' ||
          res.data.status === 'cancelled'
        ) {
          stopPolling()
          if (res.data.status === 'succeeded') {
            await fetchReport(taskId)
          }
        }
      } catch {
        // polling error - silently continue
      }
    }, intervalMs)
  }

  function stopPolling() {
    if (pollingTimer.value) {
      clearInterval(pollingTimer.value)
      pollingTimer.value = null
    }
  }

  const cancelling = ref(false)

  async function cancelTask(taskId: string) {
    cancelling.value = true
    error.value = null
    try {
      await auditsApi.cancel(taskId)
      if (currentTask.value?.task_id === taskId) {
        currentTask.value = { ...currentTask.value, status: 'cancelling' as const, can_cancel: false }
      }
      // Refresh task list if loaded
      if (tasks.value.length) {
        await fetchAllTasks()
      }
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : '取消任务失败'
    } finally {
      cancelling.value = false
    }
  }

  function selectFinding(finding: Finding | null) {
    selectedFinding.value = finding
  }

  function selectRiskVector(rv: RiskVector | null) {
    selectedRiskVector.value = rv
  }

  function getFindingsForFunction(functionId: string): Finding[] {
    if (!currentReport.value) return []
    return currentReport.value.findings.filter((f) =>
      f.evidence.some((e) => e.function_id === functionId),
    )
  }

  function $reset() {
    stopPolling()
    tasks.value = []
    currentTask.value = null
    currentReport.value = null
    loading.value = false
    error.value = null
    selectedFinding.value = null
    selectedRiskVector.value = null
    riskLevelByTask.value = {}
    taskLogs.value = null
  }

  // Find source file paths from report metadata
  function getSourceFiles(): { path: string; content: string }[] {
    // Extract from findings location info — in reality we'd get this from the report or a separate endpoint
    return []
  }

  return {
    tasks,
    currentTask,
    currentReport,
    loading,
    error,
    totalTasks,
    statusCounts,
    sortedRiskVectors,
    top10RiskVectors,
    contractSummary,
    contractProjects,
    inputContractTotal,
    normalContractCount,
    abnormalContractCount,
    confirmedFindings,
    suspectedFindings,
    anomalyWarnings,
    otherWarnings,
    selectedFinding,
    selectedRiskVector,
    cancelling,
    retrying,
    riskLevelByTask,
    riskLevelsLoading,
    taskLogs,
    cancelTask,
    fetchTasks,
    fetchAllTasks,
    ensureRiskLevels,
    retryTask,
    fetchTask,
    createTask,
    fetchReport,
    fetchTaskLogs,
    startPolling,
    stopPolling,
    selectFinding,
    selectRiskVector,
    getFindingsForFunction,
    getSourceFiles,
    $reset,
  }
})
