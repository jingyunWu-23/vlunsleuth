<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import NewTaskDialog from '@/components/dashboard/NewTaskDialog.vue'

const router = useRouter()
const auditStore = useAuditStore()

const showNewTaskDialog = ref(false)

onMounted(() => {
  auditStore.fetchTasks()
})

function openTask(taskId: string) {
  router.push(`/audit/${taskId}`)
}

function formatDate(d?: string) {
  if (!d) return '--'
  return new Date(d).toLocaleString('zh-CN')
}

const statusLabels: Record<string, string> = {
  created: '已创建',
  queued: '排队中',
  running: '检测中',
  cancelling: '取消中',
  succeeded: '已完成',
  failed: '失败',
  cancelled: '已取消',
  interrupted: '已中断',
}
</script>

<template>
  <div class="p-6 max-w-6xl mx-auto">
    <!-- Welcome section -->
    <div class="mb-8">
      <h1 class="text-2xl font-bold text-white mb-2">VulnSleuth：检索增强与多智能体协同的合约漏洞定位与修复平台</h1>
      <p class="text-gray-400 text-sm">基于多模型联合推理的智能合约漏洞检测系统 — LSTM + GCN + DeepSVDD + RAG + LLM</p>
    </div>

    <!-- Quick actions -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
      <button
        @click="showNewTaskDialog = true"
        class="flex items-center gap-4 p-5 bg-[#161b22] border border-[#30363d] rounded-xl hover:border-blue-500/50 transition-colors group"
      >
        <div class="w-12 h-12 rounded-xl bg-blue-600/20 flex items-center justify-center group-hover:bg-blue-600/30 transition-colors">
          <svg class="w-6 h-6 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
        </div>
        <div class="text-left">
          <div class="text-white text-sm font-medium">新建检测任务</div>
          <div class="text-gray-500 text-xs mt-0.5">上传 Solidity 合约开始审计</div>
        </div>
      </button>

      <button
        @click="router.push('/tasks')"
        class="flex items-center gap-4 p-5 bg-[#161b22] border border-[#30363d] rounded-xl hover:border-purple-500/50 transition-colors group"
      >
        <div class="w-12 h-12 rounded-xl bg-purple-600/20 flex items-center justify-center group-hover:bg-purple-600/30 transition-colors">
          <svg class="w-6 h-6 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <div class="text-left">
          <div class="text-white text-sm font-medium">历史任务</div>
          <div class="text-gray-500 text-xs mt-0.5">查看所有审计记录</div>
        </div>
      </button>

      <div class="flex items-center gap-4 p-5 bg-[#161b22] border border-[#30363d] rounded-xl">
        <div class="w-12 h-12 rounded-xl bg-green-600/20 flex items-center justify-center">
          <svg class="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <div>
          <div class="text-2xl font-bold text-white">{{ auditStore.statusCounts?.succeeded ?? 0 }}</div>
          <div class="text-gray-500 text-xs">已完成审计</div>
        </div>
      </div>
    </div>

    <!-- Recent tasks -->
    <div class="mb-6">
      <h2 class="text-lg font-semibold text-white mb-4">最近任务</h2>

      <div v-if="auditStore.loading" class="text-center py-12 text-gray-400">
        <svg class="animate-spin w-6 h-6 mx-auto mb-3" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        加载中...
      </div>

      <div v-else-if="!auditStore.tasks.length" class="text-center py-12 bg-[#161b22] border border-[#30363d] rounded-xl">
        <svg class="w-12 h-12 mx-auto mb-3 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <p class="text-gray-500 mb-3">暂无审计任务</p>
        <button @click="showNewTaskDialog = true" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors">
          创建第一个任务
        </button>
      </div>

      <div v-else class="space-y-3">
        <div
          v-for="task in auditStore.tasks.slice(0, 5)"
          :key="task.task_id"
          @click="openTask(task.task_id)"
          class="flex items-center gap-4 p-4 bg-[#161b22] border border-[#30363d] rounded-xl hover:border-[#484f58] transition-colors cursor-pointer"
        >
          <!-- Status dot -->
          <div class="w-2.5 h-2.5 rounded-full shrink-0"
            :class="{
              'bg-green-500': task.status === 'succeeded',
              'bg-red-500': task.status === 'failed',
              'bg-blue-500 animate-pulse': task.status === 'running',
              'bg-yellow-500': task.status === 'queued',
              'bg-gray-500': task.status === 'created',
              'bg-gray-600': task.status === 'cancelled' || task.status === 'cancelling',
            }"
          />

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1">
              <span class="text-white text-sm font-medium truncate">{{ task.contract_name || '未命名任务' }}</span>
              <span class="text-xs px-2 py-0.5 rounded-full bg-[#0d1117] text-gray-400">
                {{ statusLabels[task.status] || task.status }}
              </span>
            </div>
            <div class="text-xs text-gray-500 font-mono">{{ task.task_id }}</div>
          </div>

          <div class="text-right shrink-0">
            <div class="text-xs text-gray-400 mb-1">{{ formatDate(task.created_at) }}</div>
            <div v-if="task.status === 'running' || task.status === 'queued'" class="flex items-center gap-2">
              <div v-if="task.status === 'running'" class="w-20">
                <div class="h-1.5 bg-[#0d1117] rounded-full overflow-hidden">
                  <div class="h-full bg-blue-500 rounded-full transition-all" :style="{ width: `${task.progress}%` }" />
                </div>
              </div>
              <button
                v-if="task.can_cancel"
                @click.stop="auditStore.cancelTask(task.task_id)"
                :disabled="auditStore.cancelling"
                class="px-2.5 py-1 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-red-500/20 rounded transition-colors disabled:opacity-50"
              >
                取消
              </button>
            </div>
            <div v-else-if="task.status === 'succeeded'" class="text-xs text-green-400">查看详情 →</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Architecture Diagram -->
    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
      <h3 class="text-sm font-semibold text-white mb-4">检测流程架构</h3>
      <div class="grid grid-cols-5 gap-3 text-center text-xs">
        <div class="p-3 bg-[#0d1117] rounded-lg border border-[#30363d]">
          <div class="text-blue-400 font-medium mb-1">合约预处理</div>
          <div class="text-gray-500">Solidity解析 · 特征提取 · 字节码编译</div>
        </div>
        <div class="p-3 bg-[#0d1117] rounded-lg border border-[#30363d]">
          <div class="text-purple-400 font-medium mb-1">多模型检测</div>
          <div class="text-gray-500">LSTM · GCN · DeepSVDD · Static</div>
        </div>
        <div class="p-3 bg-[#0d1117] rounded-lg border border-[#30363d]">
          <div class="text-orange-400 font-medium mb-1">证据汇聚评分</div>
          <div class="text-gray-500">R_func 风险评分 · RAG 知识匹配</div>
        </div>
        <div class="p-3 bg-[#0d1117] rounded-lg border border-[#30363d]">
          <div class="text-cyan-400 font-medium mb-1">LLM 推理定位</div>
          <div class="text-gray-500">DeepSeek v4-pro · 漏洞推理</div>
        </div>
        <div class="p-3 bg-[#0d1117] rounded-lg border border-[#30363d]">
          <div class="text-green-400 font-medium mb-1">验证与报告</div>
          <div class="text-gray-500">Slither 验证 · 修复建议</div>
        </div>
      </div>
    </div>

    <!-- New Task Dialog -->
    <NewTaskDialog
      v-if="showNewTaskDialog"
      @close="showNewTaskDialog = false"
      @created="(taskId) => { showNewTaskDialog = false; openTask(taskId) }"
    />
  </div>
</template>
