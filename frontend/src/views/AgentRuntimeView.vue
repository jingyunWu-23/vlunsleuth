<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { reportsApi } from '@/api'
import type { AgentRuntime, AgentRuntimeResponse } from '@/types'

const route = useRoute()
const taskId = computed(() => route.params.taskId as string)
const loading = ref(false)
const error = ref('')
const runtime = ref<AgentRuntimeResponse | null>(null)
const activeAgentId = ref('')

const activeAgent = computed<AgentRuntime | null>(() =>
  runtime.value?.agents.find((item) => item.agent_id === activeAgentId.value) ?? runtime.value?.agents[0] ?? null,
)

const statusMeta: Record<string, { label: string; cls: string; dot: string }> = {
  pending: { label: '等待中', cls: 'text-gray-400 bg-gray-500/10 border-gray-500/20', dot: 'bg-gray-500' },
  running: { label: '运行中', cls: 'text-blue-300 bg-blue-500/10 border-blue-500/30', dot: 'bg-blue-400' },
  succeeded: { label: '已完成', cls: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30', dot: 'bg-emerald-400' },
  failed: { label: '失败', cls: 'text-red-300 bg-red-500/10 border-red-500/30', dot: 'bg-red-400' },
  skipped: { label: '已跳过', cls: 'text-gray-400 bg-gray-500/10 border-gray-500/20', dot: 'bg-gray-500' },
  incomplete: { label: '未完整', cls: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30', dot: 'bg-yellow-400' },
}

onMounted(fetchRuntime)

async function fetchRuntime() {
  if (!taskId.value) return
  loading.value = true
  error.value = ''
  try {
    const res = await reportsApi.getAgents(taskId.value)
    runtime.value = res.data
    activeAgentId.value = res.data.agents[0]?.agent_id ?? ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '获取智能体运行信息失败'
  } finally {
    loading.value = false
  }
}

function meta(agent: AgentRuntime | null) {
  return statusMeta[agent?.status ?? 'pending'] ?? statusMeta.pending
}

function formatTime(value?: string) {
  if (!value) return '--'
  return value.replace('T', ' ').slice(0, 19)
}

function preview(value: unknown) {
  if (value === null || value === undefined) return '--'
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value, null, 2)
}
</script>

<template>
  <div class="h-full overflow-y-auto bg-[#0d1117] text-gray-200">
    <div class="border-b border-[#30363d] px-6 py-5">
      <div class="flex items-center justify-between gap-4">
        <div>
          <h1 class="text-xl font-semibold text-white">智能体运行</h1>
          <p class="text-sm text-gray-500 mt-1">{{ taskId }} · {{ runtime?.audit_log_path || 'audit.log' }}</p>
        </div>
        <button
          @click="fetchRuntime"
          class="px-3 py-2 text-sm rounded-lg border border-[#30363d] text-gray-300 hover:bg-[#161b22] transition-colors"
        >
          刷新
        </button>
      </div>
    </div>

    <div v-if="loading" class="h-64 flex items-center justify-center text-gray-500">加载中...</div>
    <div v-else-if="error" class="m-6 p-4 border border-red-500/30 bg-red-500/10 text-red-300 rounded-lg">
      {{ error }}
    </div>

    <div v-else-if="runtime" class="grid grid-cols-[280px_1fr] min-h-[calc(100vh-96px)]">
      <aside class="border-r border-[#30363d] p-4 space-y-2">
        <button
          v-for="agent in runtime.agents"
          :key="agent.agent_id"
          @click="activeAgentId = agent.agent_id"
          class="w-full text-left p-3 rounded-lg border transition-colors"
          :class="activeAgentId === agent.agent_id ? 'border-blue-500 bg-blue-500/10' : 'border-[#30363d] hover:bg-[#161b22]'"
        >
          <div class="flex items-center justify-between gap-2">
            <span class="text-sm font-medium text-white">{{ agent.name }}</span>
            <span class="px-2 py-0.5 rounded border text-[11px]" :class="meta(agent).cls">{{ meta(agent).label }}</span>
          </div>
          <p class="text-xs text-gray-500 mt-2 line-clamp-2">{{ agent.description }}</p>
          <div class="text-xs text-gray-500 mt-2">{{ agent.duration_seconds?.toFixed?.(2) ?? '0.00' }}s · {{ agent.logs.length }} 条日志</div>
        </button>
      </aside>

      <main v-if="activeAgent" class="p-6 space-y-5">
        <section class="border border-[#30363d] bg-[#161b22] rounded-lg p-4">
          <div class="flex items-start justify-between gap-4">
            <div>
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full" :class="meta(activeAgent).dot" />
                <h2 class="text-lg font-semibold text-white">{{ activeAgent.name }}</h2>
                <span class="px-2 py-0.5 rounded border text-xs" :class="meta(activeAgent).cls">{{ meta(activeAgent).label }}</span>
              </div>
              <p class="text-sm text-gray-400 mt-2">{{ activeAgent.description }}</p>
            </div>
            <div class="text-right text-xs text-gray-500">
              <div>开始：{{ formatTime(activeAgent.started_at) }}</div>
              <div class="mt-1">结束：{{ formatTime(activeAgent.finished_at) }}</div>
              <div class="mt-1">耗时：{{ activeAgent.duration_seconds.toFixed(2) }}s</div>
            </div>
          </div>
        </section>

        <section class="grid grid-cols-2 gap-4">
          <div class="border border-[#30363d] bg-[#161b22] rounded-lg p-4">
            <h3 class="text-sm font-medium text-white mb-3">输入摘要</h3>
            <pre class="text-xs text-gray-300 whitespace-pre-wrap leading-5">{{ preview(activeAgent.inputs) }}</pre>
          </div>
          <div class="border border-[#30363d] bg-[#161b22] rounded-lg p-4">
            <h3 class="text-sm font-medium text-white mb-3">输出摘要</h3>
            <pre class="text-xs text-gray-300 whitespace-pre-wrap leading-5">{{ preview(activeAgent.outputs) }}</pre>
          </div>
        </section>

        <section class="border border-[#30363d] bg-[#161b22] rounded-lg p-4">
          <h3 class="text-sm font-medium text-white mb-4">该智能体提供给最终报告的内容</h3>
          <div v-if="!activeAgent.report_contributions.length" class="text-sm text-gray-500">暂无贡献记录</div>
          <div v-else class="space-y-4">
            <div
              v-for="block in activeAgent.report_contributions"
              :key="block.type + block.title"
              class="border border-[#30363d] rounded-lg p-3 bg-[#0d1117]"
            >
              <div class="flex items-center justify-between gap-3">
                <div>
                  <div class="text-sm text-white font-medium">{{ block.title }}</div>
                  <div class="text-xs text-gray-500 mt-1">{{ block.description }}</div>
                </div>
                <span class="text-xs text-gray-500">{{ block.items.length }} 项</span>
              </div>
              <pre class="mt-3 max-h-72 overflow-auto text-xs text-gray-300 whitespace-pre-wrap leading-5">{{ preview(block.items) }}</pre>
            </div>
          </div>
        </section>

        <section class="border border-[#30363d] bg-[#161b22] rounded-lg p-4">
          <h3 class="text-sm font-medium text-white mb-4">执行日志</h3>
          <div v-if="!activeAgent.logs.length" class="text-sm text-gray-500">暂无日志</div>
          <div v-else class="space-y-2">
            <div
              v-for="(log, idx) in activeAgent.logs"
              :key="idx"
              class="grid grid-cols-[160px_160px_1fr] gap-3 border border-[#30363d] rounded-lg p-3 bg-[#0d1117] text-xs"
            >
              <span class="text-gray-500">{{ formatTime(log.time) }}</span>
              <span class="text-blue-300">{{ log.event }}</span>
              <div>
                <div class="text-gray-200">{{ log.message }}</div>
                <pre class="text-gray-500 mt-2 whitespace-pre-wrap">{{ preview(log) }}</pre>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  </div>
</template>
