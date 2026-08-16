<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import {
  RISK_LEVEL_COLORS,
  RISK_LEVEL_LABELS,
  type AuditTask,
  type RiskLevel,
  type StageLogStatus,
  type TaskStatus,
} from '@/types'

const router = useRouter()
const auditStore = useAuditStore()

const PAGE_SIZE = 10

const statusFilter = ref<string>('')
const riskLevelFilter = ref<string>('')
const dateFrom = ref('')
const dateTo = ref('')
const page = ref(1)

const riskLevels: RiskLevel[] = ['high', 'medium', 'low', 'none']

const statusLabels: Record<TaskStatus, string> = {
  created: '已创建',
  queued: '排队中',
  running: '检测中',
  cancelling: '取消中',
  succeeded: '已完成',
  failed: '失败',
  cancelled: '已取消',
  interrupted: '已中断',
}

const statusColors: Record<TaskStatus, string> = {
  created: 'bg-gray-500',
  queued: 'bg-yellow-500',
  running: 'bg-blue-500',
  cancelling: 'bg-orange-500',
  succeeded: 'bg-green-500',
  failed: 'bg-red-500',
  cancelled: 'bg-gray-600',
  interrupted: 'bg-orange-600',
}

const stageStatusLabels: Record<StageLogStatus, string> = {
  done: '已完成',
  running: '执行中',
  pending: '待执行',
  skipped: '已跳过',
  failed: '失败',
  cancelled: '已取消',
  interrupted: '已中断',
}

const stageStatusColors: Record<StageLogStatus, string> = {
  done: 'text-green-400',
  running: 'text-blue-400',
  pending: 'text-gray-500',
  skipped: 'text-gray-600',
  failed: 'text-red-400',
  cancelled: 'text-orange-400',
  interrupted: 'text-orange-500',
}

function stageDot(status: StageLogStatus) {
  return {
    done: 'bg-green-500',
    running: 'bg-blue-500 animate-pulse',
    pending: 'bg-gray-600',
    skipped: 'bg-gray-700',
    failed: 'bg-red-500',
    cancelled: 'bg-orange-500',
    interrupted: 'bg-orange-600',
  }[status]
}

const filteredTasks = computed(() => {
  const from = dateFrom.value ? new Date(`${dateFrom.value}T00:00:00`) : null
  const to = dateTo.value ? new Date(`${dateTo.value}T23:59:59.999`) : null
  return auditStore.tasks.filter((task) => {
    if (statusFilter.value && task.status !== statusFilter.value) return false
    if (riskLevelFilter.value && auditStore.riskLevelByTask[task.task_id] !== riskLevelFilter.value) {
      return false
    }
    if (task.created_at) {
      const created = new Date(task.created_at)
      if (from && created < from) return false
      if (to && created > to) return false
    }
    return true
  })
})

const totalPages = computed(() => Math.max(1, Math.ceil(filteredTasks.value.length / PAGE_SIZE)))

const pagedTasks = computed(() =>
  filteredTasks.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE),
)

function applyFilter() {
  page.value = 1
}

function changePage(next: number) {
  page.value = Math.min(Math.max(1, next), totalPages.value)
}

function resetFilters() {
  statusFilter.value = ''
  riskLevelFilter.value = ''
  dateFrom.value = ''
  dateTo.value = ''
  applyFilter()
}

function toggleStatusFilter(status: string) {
  statusFilter.value = statusFilter.value === status ? '' : status
  applyFilter()
}

// 风险等级筛选需要所有成功任务的报告，逐条请求并缓存
watch(riskLevelFilter, (level) => {
  if (!level) return
  auditStore.ensureRiskLevels(
    auditStore.tasks.filter((t) => t.status === 'succeeded').map((t) => t.task_id),
  )
})

// 当前页展示风险等级徽标，只需拉取当前页成功任务的报告
watch(
  pagedTasks,
  (list) => {
    auditStore.ensureRiskLevels(
      list.filter((t) => t.status === 'succeeded').map((t) => t.task_id),
    )
  },
  { immediate: true },
)

onMounted(() => {
  auditStore.fetchAllTasks()
})

function viewTask(taskId: string) {
  router.push(`/audit/${taskId}`)
}

function viewReport(taskId: string) {
  router.push(`/report/${taskId}`)
}

async function retryTask(task: AuditTask) {
  if (!window.confirm(`确认复用该任务（${task.task_id.slice(0, 20)}…）的合约源码重新检测？`)) return
  const created = await auditStore.retryTask(task.task_id)
  if (created) router.push(`/audit/${created.task_id}`)
}

const showLogs = ref(false)

function openLogs(taskId: string) {
  showLogs.value = true
  auditStore.fetchTaskLogs(taskId)
}

function closeLogs() {
  showLogs.value = false
}

function formatDate(d?: string) {
  if (!d) return '--'
  return new Date(d).toLocaleString('zh-CN')
}

function formatTime(t?: string) {
  if (!t) return '--'
  return new Date(t).toLocaleTimeString('zh-CN', { hour12: false })
}

function formatDuration(seconds?: number | null) {
  if (seconds == null) return '--'
  return seconds >= 1 ? `${seconds.toFixed(1)}s` : `${Math.round(seconds * 1000)}ms`
}
</script>

<template>
  <div class="p-6">
    <!-- Header + Filters -->
    <div class="flex items-center justify-between mb-6 flex-wrap gap-3">
      <h1 class="text-xl font-bold text-white">历史任务</h1>
      <div class="flex items-center gap-3 flex-wrap">
        <select
          v-model="statusFilter"
          @change="applyFilter"
          class="px-3 py-2 bg-[#161b22] border border-[#30363d] rounded-lg text-sm text-gray-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">全部状态</option>
          <option v-for="(label, key) in statusLabels" :key="key" :value="key">{{ label }}</option>
        </select>
        <select
          v-model="riskLevelFilter"
          @change="applyFilter"
          class="px-3 py-2 bg-[#161b22] border border-[#30363d] rounded-lg text-sm text-gray-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">全部风险等级</option>
          <option v-for="level in riskLevels" :key="level" :value="level">{{ RISK_LEVEL_LABELS[level] }}</option>
        </select>
        <div class="flex items-center gap-2 text-xs text-gray-500">
          <input
            v-model="dateFrom"
            type="date"
            @change="applyFilter"
            class="px-3 py-2 bg-[#161b22] border border-[#30363d] rounded-lg text-sm text-gray-300 focus:outline-none focus:border-blue-500 [color-scheme:dark]"
          />
          <span>至</span>
          <input
            v-model="dateTo"
            type="date"
            @change="applyFilter"
            class="px-3 py-2 bg-[#161b22] border border-[#30363d] rounded-lg text-sm text-gray-300 focus:outline-none focus:border-blue-500 [color-scheme:dark]"
          />
        </div>
        <button
          @click="resetFilters"
          class="px-3 py-2 text-sm text-gray-400 hover:text-gray-200 bg-[#161b22] border border-[#30363d] rounded-lg transition-colors"
        >
          重置
        </button>
      </div>
    </div>

    <!-- Status summary pills -->
    <div class="flex items-center gap-3 mb-6 flex-wrap">
      <span
        v-for="(label, key) in statusLabels"
        :key="key"
        class="px-3 py-1 text-xs rounded-full border cursor-pointer transition-colors"
        :class="[
          statusFilter === key
            ? 'bg-blue-600/20 border-blue-600/30 text-blue-400'
            : 'bg-[#161b22] border-[#30363d] text-gray-400 hover:text-gray-200',
        ]"
        @click="toggleStatusFilter(key)"
      >
        {{ label }}: {{ auditStore.statusCounts?.[key] ?? 0 }}
      </span>
      <span v-if="auditStore.riskLevelsLoading" class="text-xs text-gray-500 flex items-center gap-1.5">
        <svg class="animate-spin w-3 h-3" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        风险等级加载中…
      </span>
    </div>

    <!-- Task Table -->
    <div v-if="auditStore.loading" class="text-center py-12 text-gray-400">
      <svg class="animate-spin w-6 h-6 mx-auto mb-3" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
      加载中...
    </div>

    <div v-else-if="!auditStore.tasks.length" class="text-center py-12 text-gray-500">
      <svg class="w-12 h-12 mx-auto mb-3 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
      </svg>
      暂无任务记录
    </div>

    <div v-else class="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-[#30363d] text-gray-400">
            <th class="text-left py-3 px-4 font-medium">任务 ID</th>
            <th class="text-left py-3 px-4 font-medium">状态</th>
            <th class="text-left py-3 px-4 font-medium">风险等级</th>
            <th class="text-left py-3 px-4 font-medium">进度</th>
            <th class="text-left py-3 px-4 font-medium">创建时间</th>
            <th class="text-left py-3 px-4 font-medium">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!pagedTasks.length">
            <td colspan="6" class="py-10 text-center text-gray-500 text-xs">无匹配的任务记录</td>
          </tr>
          <tr
            v-for="task in pagedTasks"
            :key="task.task_id"
            class="border-b border-[#1a1f2b] hover:bg-[#1c2128] transition-colors cursor-pointer"
            @click="viewTask(task.task_id)"
          >
            <td class="py-3 px-4">
              <span class="font-mono text-xs text-gray-300">{{ task.task_id.slice(0, 20) }}...</span>
            </td>
            <td class="py-3 px-4">
              <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs" :class="statusColors[task.status] + ' text-white bg-opacity-20'">
                <span class="w-1.5 h-1.5 rounded-full bg-current" />
                {{ statusLabels[task.status] }}
              </span>
            </td>
            <td class="py-3 px-4">
              <span
                v-if="task.status === 'succeeded' && auditStore.riskLevelByTask[task.task_id]"
                class="inline-flex px-2 py-0.5 rounded-full text-xs"
                :class="RISK_LEVEL_COLORS[auditStore.riskLevelByTask[task.task_id]]"
              >
                {{ RISK_LEVEL_LABELS[auditStore.riskLevelByTask[task.task_id]] }}
              </span>
              <span v-else class="text-xs text-gray-600">--</span>
            </td>
            <td class="py-3 px-4">
              <div class="flex items-center gap-2">
                <div class="flex-1 h-1.5 bg-[#0d1117] rounded-full overflow-hidden max-w-[100px]">
                  <div
                    class="h-full rounded-full transition-all duration-500"
                    :class="task.status === 'succeeded' ? 'bg-green-500' : task.status === 'failed' ? 'bg-red-500' : 'bg-blue-500'"
                    :style="{ width: `${task.progress}%` }"
                  />
                </div>
                <span class="text-xs text-gray-500 w-8">{{ task.progress }}%</span>
              </div>
            </td>
            <td class="py-3 px-4 text-gray-500 text-xs">{{ formatDate(task.created_at) }}</td>
            <td class="py-3 px-4">
              <div class="flex items-center gap-3">
                <button
                  @click.stop="openLogs(task.task_id)"
                  class="text-xs text-purple-400 hover:text-purple-300"
                >
                  日志
                </button>
                <button
                  v-if="task.status === 'succeeded'"
                  @click.stop="viewReport(task.task_id)"
                  class="text-xs text-green-400 hover:text-green-300"
                >
                  查看报告
                </button>
                <button
                  v-if="task.can_retry"
                  @click.stop="retryTask(task)"
                  :disabled="auditStore.retrying"
                  class="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50"
                >
                  重试
                </button>
                <button
                  v-if="task.can_cancel"
                  @click.stop="auditStore.cancelTask(task.task_id)"
                  :disabled="auditStore.cancelling"
                  class="text-xs text-red-400 hover:text-red-300 disabled:opacity-50"
                >
                  取消
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    <div v-if="auditStore.tasks.length" class="flex items-center justify-between mt-4 text-sm text-gray-400">
      <span>共 {{ filteredTasks.length }} 条记录</span>
      <div class="flex items-center gap-3">
        <button
          @click="changePage(page - 1)"
          :disabled="page <= 1"
          class="px-3 py-1.5 rounded-lg bg-[#161b22] border border-[#30363d] text-gray-300 hover:text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          上一页
        </button>
        <span>第 {{ page }} / {{ totalPages }} 页</span>
        <button
          @click="changePage(page + 1)"
          :disabled="page >= totalPages"
          class="px-3 py-1.5 rounded-lg bg-[#161b22] border border-[#30363d] text-gray-300 hover:text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          下一页
        </button>
      </div>
    </div>

    <!-- Pipeline Logs Dialog -->
    <div
      v-if="showLogs"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      @click.self="closeLogs"
    >
      <div class="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-2xl max-h-[85vh] flex flex-col mx-4">
        <div class="flex items-center justify-between px-5 py-4 border-b border-[#30363d] shrink-0">
          <div>
            <h3 class="text-sm font-semibold text-white">流水线执行日志</h3>
            <p class="text-xs text-gray-500 font-mono mt-0.5">{{ auditStore.taskLogs?.task.task_id }}</p>
          </div>
          <button @click="closeLogs" class="text-gray-500 hover:text-gray-300 transition-colors">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div class="flex-1 overflow-y-auto p-5">
          <div v-if="auditStore.loading && !auditStore.taskLogs" class="text-center py-10 text-gray-400">
            <svg class="animate-spin w-6 h-6 mx-auto mb-3" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            日志加载中...
          </div>

          <template v-else-if="auditStore.taskLogs">
            <!-- Overall info -->
            <div class="flex items-center gap-6 text-xs text-gray-400 mb-4 flex-wrap">
              <span>
                状态:
                <span class="text-gray-200">{{ statusLabels[auditStore.taskLogs.task.status] }}</span>
              </span>
              <span v-if="auditStore.taskLogs.total_seconds != null">
                总耗时: <span class="text-gray-200">{{ auditStore.taskLogs.total_seconds.toFixed(1) }}s</span>
              </span>
              <span>开始: {{ formatDate(auditStore.taskLogs.task.started_at) }}</span>
              <span>结束: {{ formatDate(auditStore.taskLogs.task.finished_at) }}</span>
            </div>

            <!-- Pipeline stages -->
            <div class="space-y-1.5 mb-6">
              <div
                v-for="stage in auditStore.taskLogs.stages"
                :key="stage.key"
                class="flex items-center gap-3 px-3 py-2 rounded-lg bg-[#0d1117] border border-[#21262d]"
              >
                <span class="w-2 h-2 rounded-full shrink-0" :class="stageDot(stage.status)" />
                <span class="flex-1 text-sm text-gray-300">{{ stage.label }}</span>
                <span class="text-xs text-gray-600">
                  {{ stage.progress_start }}-{{ stage.progress_end }}%
                </span>
                <span
                  class="text-xs w-16 text-right"
                  :class="stage.status === 'running' ? 'text-blue-400' : 'text-gray-500'"
                >
                  {{ formatDuration(stage.seconds) }}
                </span>
                <span class="text-xs w-14 text-right" :class="stageStatusColors[stage.status]">
                  {{ stageStatusLabels[stage.status] }}
                </span>
              </div>
            </div>

            <!-- Events -->
            <h4 class="text-xs font-medium text-gray-400 mb-2">事件记录</h4>
            <div class="space-y-1.5">
              <div
                v-for="(event, i) in auditStore.taskLogs.events"
                :key="i"
                class="flex items-start gap-3 text-xs"
              >
                <span class="text-gray-600 font-mono shrink-0">{{ formatTime(event.time) }}</span>
                <span class="text-gray-400">{{ event.message }}</span>
              </div>
              <div v-if="!auditStore.taskLogs.events.length" class="text-xs text-gray-600">暂无事件记录</div>
            </div>
          </template>

          <div v-else class="text-center py-10 text-gray-500">{{ auditStore.error || '暂无日志数据' }}</div>
        </div>
      </div>
    </div>
  </div>
</template>
