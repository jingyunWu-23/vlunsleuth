<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import { useCallGraph } from '@/composables/useCallGraph'
import CallGraph from '@/components/dashboard/CallGraph.vue'
import type { CallGraphNode } from '@/types'

const route = useRoute()
const router = useRouter()
const auditStore = useAuditStore()

const callGraphRef = ref<InstanceType<typeof CallGraph> | null>(null)
const selectedNode = ref<CallGraphNode | null>(null)
const hoveredEdgeLabel = ref('')

// Accept ?task_id=... query param or use latest task
const taskIdParam = route.query.task_id as string | undefined

// Report accessor (reactive getter for composable)
const report = () => auditStore.currentReport

const { graphData, summary } = useCallGraph(report)

// Stats cards
const statCards = computed(() => [
  { label: '合约节点', value: graphData.value.nodes.filter((n) => n.category === 'contract').length, color: 'text-green-400', bg: 'bg-green-500/10' },
  { label: '函数节点', value: graphData.value.nodes.filter((n) => n.category === 'function').length, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  { label: '调用边', value: summary.value.totalCallEdges, color: 'text-purple-400', bg: 'bg-purple-500/10' },
  { label: '风险边', value: summary.value.riskEdges, color: 'text-red-400', bg: 'bg-red-500/10' },
  { label: '跨合约风险发现', value: summary.value.crossContractFindings, color: 'text-orange-400', bg: 'bg-orange-500/10' },
])

onMounted(async () => {
  // If a specific task ID is in the URL, load it
  if (taskIdParam) {
    await auditStore.fetchTask(taskIdParam)
    if (auditStore.currentTask?.status === 'succeeded') {
      await auditStore.fetchReport(taskIdParam)
    }
  } else if (auditStore.currentTask) {
    // Reuse already-loaded task
    if (!auditStore.currentReport && auditStore.currentTask.status === 'succeeded') {
      await auditStore.fetchReport(auditStore.currentTask.task_id)
    }
  }
})

function handleNodeClick(node: CallGraphNode) {
  selectedNode.value = node
}

function handleReset() {
  callGraphRef.value?.resetView()
}

function goToAudit() {
  const tid = auditStore.currentTask?.task_id
  if (tid) router.push(`/audit/${tid}`)
}
</script>

<template>
  <div class="flex flex-col h-full">
    <!-- Header -->
    <div class="flex items-center justify-between px-6 py-4 border-b border-[#30363d] shrink-0">
      <div>
        <h1 class="text-lg font-bold text-white">跨合约调用图</h1>
        <p class="text-xs text-gray-500 mt-0.5">GCN 跨合约风险检测 — 合约间调用关系可视化</p>
      </div>
      <div class="flex items-center gap-3">
        <!-- Task selector hint -->
        <span v-if="auditStore.currentTask" class="text-xs text-gray-500">
          当前任务:
          <span class="text-gray-300 font-mono">{{ auditStore.currentTask.task_id.slice(0, 16) }}...</span>
        </span>
        <button
          v-if="!auditStore.currentReport"
          @click="goToAudit"
          class="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          选择审计任务
        </button>
      </div>
    </div>

    <!-- Loading -->
    <div v-if="auditStore.loading" class="flex items-center justify-center flex-1">
      <svg class="animate-spin w-8 h-8 text-blue-400" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
    </div>

    <!-- Main content -->
    <template v-else>
      <!-- Stat cards row -->
      <div class="grid grid-cols-5 gap-3 px-6 py-4 shrink-0">
        <div
          v-for="card in statCards"
          :key="card.label"
          class="flex items-center gap-3 px-4 py-3 bg-[#161b22] border border-[#30363d] rounded-xl"
        >
          <div class="w-9 h-9 rounded-lg flex items-center justify-center shrink-0" :class="card.bg">
            <span class="text-lg font-bold" :class="card.color">{{ card.value }}</span>
          </div>
          <span class="text-xs text-gray-400 leading-tight">{{ card.label }}</span>
        </div>
      </div>

      <!-- Graph + Detail panel -->
      <div class="flex-1 flex overflow-hidden min-h-0 px-6 pb-4 gap-4">
        <!-- Graph -->
        <div class="flex-1 min-w-0">
          <CallGraph
            ref="callGraphRef"
            :data="graphData"
            @node-click="handleNodeClick"
            @edge-hover="(e) => (hoveredEdgeLabel = e.methodName ?? '')"
          />
        </div>

        <!-- Detail side panel -->
        <div class="w-72 shrink-0 bg-[#161b22] border border-[#30363d] rounded-xl overflow-y-auto">
          <div v-if="!selectedNode" class="flex flex-col items-center justify-center h-full text-gray-600 p-4">
            <svg class="w-10 h-10 mb-3 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" />
            </svg>
            <p class="text-sm text-center">点击图中节点<br/>查看详情</p>
          </div>

          <template v-else>
            <div class="p-4 border-b border-[#30363d]">
              <div class="flex items-center gap-2 mb-2">
                <span
                  class="px-2 py-0.5 text-xs rounded border"
                  :class="{
                    'text-red-400 bg-red-500/10 border-red-500/30': selectedNode.riskLevel === 'high',
                    'text-orange-400 bg-orange-500/10 border-orange-500/30': selectedNode.riskLevel === 'medium',
                    'text-green-400 bg-green-500/10 border-green-500/30': selectedNode.riskLevel === 'none',
                    'text-yellow-400 bg-yellow-500/10 border-yellow-500/30': selectedNode.riskLevel === 'low',
                  }"
                >
                  {{ selectedNode.category === 'contract' ? '合约' : '函数' }}
                </span>
                <span
                  v-if="selectedNode.riskLevel !== 'none'"
                  class="px-2 py-0.5 text-xs rounded"
                  :class="{
                    'bg-red-600/20 text-red-400': selectedNode.riskLevel === 'high',
                    'bg-orange-600/20 text-orange-400': selectedNode.riskLevel === 'medium',
                    'bg-yellow-600/20 text-yellow-400': selectedNode.riskLevel === 'low',
                  }"
                >
                  {{ selectedNode.riskLevel === 'high' ? '高风险' : selectedNode.riskLevel === 'medium' ? '中风险' : '低风险' }}
                </span>
              </div>
              <h3 class="text-white text-sm font-medium break-all">{{ selectedNode.name }}</h3>
              <p class="text-xs text-gray-500 mt-1">所属合约: {{ selectedNode.contractName }}</p>
            </div>

            <div class="p-4 space-y-4">
              <div>
                <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">节点信息</h4>
                <dl class="space-y-2 text-xs">
                  <div class="flex justify-between">
                    <dt class="text-gray-500">类型</dt>
                    <dd class="text-gray-300">{{ selectedNode.category === 'contract' ? '智能合约' : '合约函数' }}</dd>
                  </div>
                  <div class="flex justify-between">
                    <dt class="text-gray-500">跨合约风险发现</dt>
                    <dd :class="selectedNode.crossContractFindings > 0 ? 'text-red-400' : 'text-gray-300'">
                      {{ selectedNode.crossContractFindings }}
                    </dd>
                  </div>
                  <div v-if="selectedNode.rFunc !== undefined" class="flex justify-between">
                    <dt class="text-gray-500">R_func 风险分</dt>
                    <dd
                      :class="{
                        'text-red-400': (selectedNode.rFunc ?? 0) >= 0.7,
                        'text-orange-400': (selectedNode.rFunc ?? 0) >= 0.45 && (selectedNode.rFunc ?? 0) < 0.7,
                        'text-green-400': (selectedNode.rFunc ?? 0) < 0.35,
                      }"
                      class="font-mono"
                    >
                      {{ selectedNode.rFunc.toFixed(3) }}
                    </dd>
                  </div>
                </dl>
              </div>

              <div v-if="selectedNode.crossContractFindings > 0">
                <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">GCN 检测说明</h4>
                <p class="text-xs text-gray-400 leading-relaxed">
                  该{{ selectedNode.category === 'contract' ? '合约' : '函数' }}在跨合约调用图分析中检测到
                  <span class="text-red-400">{{ selectedNode.crossContractFindings }}</span>
                  个潜在风险。GCN (图卷积网络) 模型通过分析合约间调用拓扑结构，识别异常调用模式。
                </p>
              </div>

              <!-- Link to full audit -->
              <button
                v-if="auditStore.currentTask"
                @click="goToAudit"
                class="w-full py-2 text-xs bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/20 rounded-lg transition-colors"
              >
                查看完整审计详情 →
              </button>
            </div>
          </template>
        </div>
      </div>
    </template>
  </div>
</template>
