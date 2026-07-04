import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { auditsApi, reportsApi } from '@/api'
import type { AuditTask, AuditReport, RiskVector, Finding, Warning, AuditMode, VulnerabilityId } from '@/types'

export const useAuditStore = defineStore('audit', () => {
  const tasks = ref<AuditTask[]>([])
  const currentTask = ref<AuditTask | null>(null)
  const currentReport = ref<AuditReport | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const pollingTimer = ref<ReturnType<typeof setInterval> | null>(null)

  const totalTasks = ref(0)
  const statusCounts = ref<Record<string, number>>({})

  const sortedRiskVectors = computed(() => {
    if (!currentReport.value?.risk_vectors) return []
    return [...currentReport.value.risk_vectors].sort((a, b) => b.r_func - a.r_func)
  })

  const top10RiskVectors = computed(() => sortedRiskVectors.value.slice(0, 10))

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
    confirmedFindings,
    suspectedFindings,
    anomalyWarnings,
    otherWarnings,
    selectedFinding,
    selectedRiskVector,
    fetchTasks,
    fetchTask,
    createTask,
    fetchReport,
    startPolling,
    stopPolling,
    selectFinding,
    selectRiskVector,
    getFindingsForFunction,
    getSourceFiles,
    $reset,
  }
})
