<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import type { TaskStatus } from '@/types'

const router = useRouter()
const auditStore = useAuditStore()

const statusFilter = ref<string>('')

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

onMounted(() => {
  auditStore.fetchTasks()
})

function applyFilter() {
  auditStore.fetchTasks({ status: statusFilter.value || undefined })
}

function viewTask(taskId: string) {
  router.push(`/audit/${taskId}`)
}

function formatDate(d?: string) {
  if (!d) return '--'
  return new Date(d).toLocaleString('zh-CN')
}
</script>

<template>
  <div class="p-6">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-xl font-bold text-white">历史任务</h1>
      <div class="flex items-center gap-3">
        <select
          v-model="statusFilter"
          @change="applyFilter"
          class="px-3 py-2 bg-[#161b22] border border-[#30363d] rounded-lg text-sm text-gray-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">全部状态</option>
          <option v-for="(label, key) in statusLabels" :key="key" :value="key">{{ label }}</option>
        </select>
      </div>
    </div>

    <!-- Status summary pills -->
    <div class="flex items-center gap-3 mb-6 flex-wrap">
      <span
        v-for="(label, key) in statusLabels"
        :key="key"
        class="px-3 py-1 text-xs rounded-full border"
        :class="[
          statusFilter === key
            ? 'bg-blue-600/20 border-blue-600/30 text-blue-400'
            : 'bg-[#161b22] border-[#30363d] text-gray-400',
        ]"
      >
        {{ label }}: {{ auditStore.statusCounts?.[key] ?? 0 }}
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
            <th class="text-left py-3 px-4 font-medium">进度</th>
            <th class="text-left py-3 px-4 font-medium">合约</th>
            <th class="text-left py-3 px-4 font-medium">创建时间</th>
            <th class="text-left py-3 px-4 font-medium">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="task in auditStore.tasks"
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
            <td class="py-3 px-4 text-gray-300 text-xs">{{ task.contract_name || '--' }}</td>
            <td class="py-3 px-4 text-gray-500 text-xs">{{ formatDate(task.created_at) }}</td>
            <td class="py-3 px-4">
              <button
                v-if="task.can_retry"
                @click.stop="auditStore.fetchTask(task.task_id); /* will add retry logic */"
                class="text-xs text-blue-400 hover:text-blue-300"
              >
                重试
              </button>
              <span v-else class="text-xs text-gray-600">--</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    <div v-if="auditStore.totalTasks > 0" class="flex items-center justify-between mt-4 text-sm text-gray-400">
      <span>共 {{ auditStore.totalTasks }} 条记录</span>
    </div>
  </div>
</template>
