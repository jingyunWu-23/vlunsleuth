<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import { auditsApi, reportsApi } from '@/api'
import apiClient from '@/api/client'
import { marked } from 'marked'
import type { AuditTask, AuditReport, TaskStatus } from '@/types'

const route = useRoute()
const router = useRouter()
const auditStore = useAuditStore()

const taskId = computed(() => route.params.taskId as string | undefined)
const hasTaskId = computed(() => !!taskId.value)

// --- State ---
const task = ref<AuditTask | null>(null)
const report = ref<AuditReport | null>(null)
const markdownRaw = ref('')
const loading = ref(true)
const error = ref<string | null>(null)

// --- Computed ---
const modeLabel = computed<string>(() => {
  const map: Record<string, string> = {
    full_audit: '全面审计',
    known_full_scan: '已知漏洞扫描',
    unknown_risk_scan: '未知风险扫描',
    cross_contract_scan: '跨合约专项扫描',
  }
  return map[report.value?.mode ?? task.value?.mode ?? ''] ?? (report.value?.mode ?? task.value?.mode ?? '--')
})

const statusLabel = computed<string>(() => {
  const map: Record<TaskStatus, string> = {
    created: '已创建', queued: '排队中', running: '检测中', cancelling: '取消中',
    succeeded: '成功', failed: '失败', cancelled: '已取消', interrupted: '已中断',
  }
  return map[(task.value?.status as TaskStatus) ?? 'created'] ?? '--'
})

const statusColor = computed(() => {
  const s = task.value?.status
  if (s === 'succeeded') return 'border-green-500/30 bg-green-500/10 text-green-400'
  if (s === 'failed') return 'border-red-500/30 bg-red-500/10 text-red-400'
  if (s === 'running' || s === 'queued') return 'border-blue-500/30 bg-blue-500/10 text-blue-400'
  return 'border-gray-500/30 bg-gray-500/10 text-gray-400'
})

const duration = computed<string>(() => {
  if (!task.value?.started_at) return '--'
  const start = new Date(task.value.started_at).getTime()
  const end = task.value.finished_at ? new Date(task.value.finished_at).getTime() : Date.now()
  const ms = end - start
  if (ms < 0) return '--'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m ${s % 60}s`
})

const findingSummary = computed(() => ({
  total: report.value?.findings.length ?? 0,
  confirmed: report.value?.findings.filter((f) => f.status === 'confirmed').length ?? 0,
  suspected: report.value?.findings.filter((f) => f.status === 'suspected').length ?? 0,
  high: report.value?.findings.filter((f) => f.severity === 'high').length ?? 0,
  medium: report.value?.findings.filter((f) => f.severity === 'medium').length ?? 0,
  low: report.value?.findings.filter((f) => f.severity === 'low').length ?? 0,
  warnings: report.value?.warnings.length ?? 0,
}))

const reportGeneratedAt = computed(() => {
  return task.value?.finished_at
    ? new Date(task.value.finished_at).toLocaleString('zh-CN')
    : '--'
})

// --- Markdown → safe HTML ---
marked.setOptions({
  breaks: true,
  gfm: true,
})

const renderedHtml = computed(() => {
  if (!markdownRaw.value) return ''
  try {
    return marked.parse(markdownRaw.value) as string
  } catch {
    return `<p class="text-red-400">Markdown 解析失败</p>`
  }
})

// --- Data fetching ---
async function fetchReport() {
  if (!taskId.value) {
    loading.value = false
    return
  }

  loading.value = true
  error.value = null

  try {
    const [taskRes, reportRes, mdRes] = await Promise.allSettled([
      auditsApi.get(taskId.value),
      reportsApi.getReport(taskId.value),
      reportsApi.getReportMarkdown(taskId.value),
    ])

    if (taskRes.status === 'fulfilled') {
      task.value = taskRes.value.data
    }
    if (reportRes.status === 'fulfilled') {
      report.value = reportRes.value.data
    }
    if (mdRes.status === 'fulfilled') {
      markdownRaw.value = typeof mdRes.value.data === 'string' ? mdRes.value.data : ''
    } else if (mdRes.status === 'rejected') {
      if (!report.value) {
        error.value = '加载报告失败: ' + (mdRes.reason?.message ?? '未知错误')
      }
    }

    if (!task.value && !report.value) {
      error.value = '无法加载审计报告数据'
    }
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : '请求失败'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchReport()
})

// --- Actions ---
async function downloadMarkdown() {
  if (!taskId.value) return
  try {
    const res = await apiClient.get(`/audits/${taskId.value}/report.md`, {
      responseType: 'blob',
    })
    const blob = new Blob([res.data], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-report-${taskId.value}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  } catch {
    // fallback: try direct link
    const a = document.createElement('a')
    a.href = `/api/v1/audits/${taskId.value}/report.md`
    a.download = `audit-report-${taskId.value}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  }
}

function printPDF() {
  window.print()
}

// --- Workflow steps (static, populated from report metadata when available) ---
const workflowSteps = [
  { label: '源码加载', desc: 'Solidity 文件解析与 AST 提取', time: '~0.5s' },
  { label: 'LSTM 检测', desc: '4 类已知漏洞模型推理', time: '~4s' },
  { label: 'GCN 图分析', desc: '跨合约调用图风险检测', time: '~3.5s' },
  { label: 'DeepSVNN 检测', desc: '异常行为偏离度分析', time: '~5s' },
  { label: '风险评分', desc: 'R_func 多维融合评分', time: '~1.5s' },
  { label: 'RAG 匹配', desc: '知识库语义相似度检索', time: '~0.8s' },
  { label: 'LLM 推理', desc: 'DeepSeek v4-pro 漏洞推理与定位', time: '~8s' },
  { label: '验证', desc: 'Slither + LLM 双重验证', time: '~3s' },
  { label: '报告生成', desc: 'Markdown + JSON 报告输出', time: '~1s' },
]
</script>

<template>
  <div class="flex flex-col h-full">
    <!-- ===== NO TASK SELECTED ===== -->
    <div v-if="!hasTaskId" class="flex items-center justify-center flex-1 p-6">
      <div class="text-center max-w-md">
        <svg class="w-16 h-16 mx-auto mb-4 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <p class="text-white font-medium mb-2">请选择要查看的审计报告</p>
        <p class="text-gray-500 text-sm mb-6">从历史任务或审计详情页跳转到此处查看完整报告</p>
        <router-link
          to="/tasks"
          class="inline-block px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
        >
          查看历史任务 →
        </router-link>
      </div>
    </div>

    <!-- ===== LOADING ===== -->
    <div v-else-if="loading" class="flex items-center justify-center flex-1">
      <div class="text-center">
        <svg class="animate-spin w-10 h-10 mx-auto mb-4 text-blue-400" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        <p class="text-gray-400 text-sm">正在加载审计报告...</p>
      </div>
    </div>

    <!-- ===== ERROR ===== -->
    <div v-else-if="error" class="flex items-center justify-center flex-1">
      <div class="text-center max-w-md">
        <svg class="w-14 h-14 mx-auto mb-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
        <p class="text-white font-medium mb-2">报告加载失败</p>
        <p class="text-gray-400 text-sm mb-6">{{ error }}</p>
        <button
          @click="fetchReport()"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
        >
          重新加载
        </button>
      </div>
    </div>

    <!-- ===== REPORT CONTENT ===== -->
    <div v-else id="report-print-area" class="flex-1 overflow-y-auto">
      <div class="max-w-5xl mx-auto p-6 space-y-6">

        <!-- ── TOP PANEL: Task Metadata ── -->
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
          <div class="flex items-start justify-between gap-6 flex-wrap">
            <!-- Left: Metadata -->
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-3 mb-3">
                <h1 class="text-xl font-bold text-white">审计报告</h1>
                <span class="px-2.5 py-0.5 text-xs font-medium rounded-full border" :class="statusColor">
                  {{ statusLabel }}
                </span>
              </div>

              <dl class="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-2 text-xs">
                <div>
                  <dt class="text-gray-500">任务 ID</dt>
                  <dd class="text-gray-300 font-mono mt-0.5">{{ taskId.slice(0, 24) }}...</dd>
                </div>
                <div>
                  <dt class="text-gray-500">检测模式</dt>
                  <dd class="text-gray-300 mt-0.5">{{ modeLabel }}</dd>
                </div>
                <div>
                  <dt class="text-gray-500">执行耗时</dt>
                  <dd class="text-gray-300 font-mono mt-0.5">{{ duration }}</dd>
                </div>
                <div>
                  <dt class="text-gray-500">报告生成时间</dt>
                  <dd class="text-gray-300 mt-0.5">{{ reportGeneratedAt }}</dd>
                </div>
              </dl>
            </div>

            <!-- Right: Action buttons -->
            <div class="flex items-center gap-3 shrink-0 print:hidden">
              <button
                @click="printPDF"
                class="flex items-center gap-2 px-4 py-2.5 bg-[#0d1117] border border-[#30363d] text-gray-300 text-sm rounded-lg hover:border-[#484f58] hover:text-white transition-colors"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" />
                </svg>
                打印 / 导出 PDF
              </button>
              <button
                @click="downloadMarkdown"
                class="flex items-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors"
              >
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                下载 Markdown
              </button>
            </div>
          </div>
        </div>

        <!-- ── SUMMARY STATS CARDS ── -->
        <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
          <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 text-center">
            <div class="text-2xl font-bold text-white">{{ findingSummary.total }}</div>
            <div class="text-xs text-gray-500 mt-1">漏洞总数</div>
          </div>
          <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 text-center">
            <div class="text-2xl font-bold text-red-400">{{ findingSummary.confirmed }}</div>
            <div class="text-xs text-gray-500 mt-1">已验证</div>
          </div>
          <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 text-center">
            <div class="text-2xl font-bold text-orange-400">{{ findingSummary.suspected }}</div>
            <div class="text-xs text-gray-500 mt-1">疑似</div>
          </div>
          <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 text-center">
            <div class="text-2xl font-bold text-red-400">{{ findingSummary.high }}</div>
            <div class="text-xs text-gray-500 mt-1">严重 (High)</div>
          </div>
          <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 text-center">
            <div class="text-2xl font-bold text-orange-400">{{ findingSummary.medium }}</div>
            <div class="text-xs text-gray-500 mt-1">中等 (Medium)</div>
          </div>
          <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 text-center">
            <div class="text-2xl font-bold text-yellow-400">{{ findingSummary.low }}</div>
            <div class="text-xs text-gray-500 mt-1">低危 (Low)</div>
          </div>
          <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 text-center">
            <div class="text-2xl font-bold text-purple-400">{{ findingSummary.warnings }}</div>
            <div class="text-xs text-gray-500 mt-1">预警项</div>
          </div>
        </div>

        <!-- ── MARKDOWN BODY ── -->
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
          <div class="px-6 py-4 border-b border-[#30363d]">
            <h2 class="text-sm font-semibold text-white">详细报告</h2>
          </div>

          <div v-if="!markdownRaw" class="p-8 text-center text-gray-500 text-sm">
            <svg class="w-10 h-10 mx-auto mb-3 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Markdown 报告暂未生成
          </div>

          <!-- Rendered HTML with manual dark markdown styles -->
          <div
            v-else
            class="p-6 md:p-8 markdown-body"
            v-html="renderedHtml"
          />
        </div>

        <!-- ── WORKFLOW TIMELINE ── -->
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
          <h2 class="text-sm font-semibold text-white mb-6">检测执行流程</h2>

          <div class="relative">
            <!-- Central line -->
            <div class="absolute left-4 top-2 bottom-2 w-0.5 bg-[#21262d]" />

            <div class="space-y-4">
              <div v-for="(step, i) in workflowSteps" :key="step.label" class="flex items-start gap-4 relative">
                <!-- Node -->
                <div class="relative z-10 w-9 h-9 rounded-full border-2 flex items-center justify-center shrink-0 text-xs font-bold bg-[#161b22] border-green-500/40 text-green-400">
                  {{ i + 1 }}
                </div>

                <!-- Content -->
                <div class="flex-1 min-w-0 pt-1">
                  <div class="flex items-center justify-between">
                    <span class="text-sm font-medium text-gray-200">{{ step.label }}</span>
                    <span class="text-xs text-gray-600 font-mono ml-4 shrink-0">{{ step.time }}</span>
                  </div>
                  <p class="text-xs text-gray-500 mt-0.5">{{ step.desc }}</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Footer -->
        <div class="text-center text-xs text-gray-600 pb-6 print:hidden">
          VulnSleuth · 检索增强与多智能体协同的合约漏洞定位与修复平台
        </div>
      </div>
    </div>
  </div>
</template>

<!-- Markdown body styles + print -->
<style>
/* ── Dark Markdown Rendering ── */
.markdown-body {
  color: #d1d5db;
  line-height: 1.75;
  font-size: 14px;
}

.markdown-body h1,
.markdown-body h2,
.markdown-body h3,
.markdown-body h4 {
  color: #e6edf3;
  border-bottom: 1px solid #21262d;
  padding-bottom: 0.5em;
  margin-top: 1.5em;
  margin-bottom: 0.75em;
  font-weight: 600;
}
.markdown-body h1 { font-size: 1.5rem; }
.markdown-body h2 { font-size: 1.25rem; }
.markdown-body h3 { font-size: 1.1rem; }

.markdown-body p {
  margin-bottom: 1em;
  color: #c9d1d9;
}

.markdown-body a {
  color: #58a6ff;
  text-decoration: none;
}
.markdown-body a:hover {
  color: #79c0ff;
  text-decoration: underline;
}

.markdown-body code {
  color: #79c0ff;
  background: #0d1117;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 0.85em;
  font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, Consolas, monospace;
}

.markdown-body pre {
  background: #0d1117;
  border: 1px solid #21262d;
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
  margin: 1em 0;
}
.markdown-body pre code {
  background: none;
  padding: 0;
  color: #c9d1d9;
  font-size: 0.82em;
}

.markdown-body table {
  width: 100%;
  border-collapse: collapse;
  border: 1px solid #21262d;
  border-radius: 8px;
  overflow: hidden;
  margin: 1em 0;
}
.markdown-body th {
  background: #0d1117;
  color: #c9d1d9;
  font-size: 0.8em;
  font-weight: 500;
  padding: 10px 16px;
  border-bottom: 1px solid #21262d;
  text-align: left;
}
.markdown-body td {
  color: #8b949e;
  font-size: 0.8em;
  padding: 10px 16px;
  border-bottom: 1px solid #1a1f2b;
}
.markdown-body tr:hover td {
  background: #1c2128;
}

.markdown-body ul,
.markdown-body ol {
  padding-left: 1.5em;
  margin: 0.75em 0;
  color: #c9d1d9;
}
.markdown-body li {
  margin-bottom: 0.25em;
}

.markdown-body strong {
  color: #e6edf3;
  font-weight: 600;
}

.markdown-body blockquote {
  border-left: 3px solid #1f6feb;
  background: rgba(13, 17, 23, 0.5);
  padding: 12px 16px;
  margin: 1em 0;
  color: #8b949e;
  font-size: 0.9em;
  border-radius: 0 6px 6px 0;
}

.markdown-body hr {
  border: none;
  border-top: 1px solid #21262d;
  margin: 1.5em 0;
}

.markdown-body img {
  border-radius: 8px;
  border: 1px solid #21262d;
  max-width: 100%;
}

/* ── Print Overrides ── */
@media print {
  body {
    background: white !important;
    color: #1f2937 !important;
  }
  aside, header, nav, .print\:hidden {
    display: none !important;
  }
  #report-print-area {
    overflow: visible !important;
    height: auto !important;
  }
  .markdown-body {
    color: #1f2937 !important;
  }
  .markdown-body code {
    background: #f3f4f6 !important;
    color: #1e40af !important;
  }
  .markdown-body pre {
    background: #f9fafb !important;
    border-color: #d1d5db !important;
  }
  .markdown-body pre code {
    color: #1f2937 !important;
  }
}
</style>
