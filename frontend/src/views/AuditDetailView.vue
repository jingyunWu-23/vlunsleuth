<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import TopCards from '@/components/dashboard/TopCards.vue'
import CodeEditor from '@/components/editor/CodeEditor.vue'
import FindingDetailPanel from '@/components/panels/FindingDetailPanel.vue'
import TimelinePanel from '@/components/analytics/TimelinePanel.vue'
import RiskRankingTable from '@/components/analytics/RiskRankingTable.vue'
import RadarChart from '@/components/analytics/RadarChart.vue'
import RiskWarningList from '@/components/analytics/RiskWarningList.vue'
import type { Finding } from '@/types'

const route = useRoute()
const auditStore = useAuditStore()
const taskId = route.params.taskId as string

const activeBottomTab = ref<'timeline' | 'ranking' | 'radar' | 'warnings'>('ranking')
const selectedFinding = ref<Finding | null>(null)

onMounted(async () => {
  await auditStore.fetchTask(taskId)
  if (auditStore.currentTask?.status === 'succeeded') {
    await auditStore.fetchReport(taskId)
  } else if (
    auditStore.currentTask?.status === 'running' ||
    auditStore.currentTask?.status === 'queued' ||
    auditStore.currentTask?.status === 'created'
  ) {
    auditStore.startPolling(taskId)
  }
})

onUnmounted(() => {
  auditStore.stopPolling()
})

function handleFindingSelect(finding: Finding) {
  selectedFinding.value = finding
}

const bottomTabs = [
  { key: 'timeline' as const, label: '执行流程' },
  { key: 'ranking' as const, label: '函数风险排名 TOP 10' },
  { key: 'radar' as const, label: '风险分数组成' },
  { key: 'warnings' as const, label: '其他潜在风险' },
]
</script>

<template>
  <div class="flex flex-col h-full">
    <!-- Loading State -->
    <div v-if="auditStore.loading && !auditStore.currentTask" class="flex items-center justify-center h-64">
      <svg class="animate-spin w-8 h-8 text-blue-400" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
    </div>

    <!-- Running State -->
    <div v-else-if="auditStore.currentTask?.status === 'running' || auditStore.currentTask?.status === 'queued'" class="flex items-center justify-center h-64 flex-col gap-4">
      <svg class="animate-spin w-10 h-10 text-blue-400" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
      <div class="text-center">
        <p class="text-white font-medium mb-1">检测进行中...</p>
        <p class="text-gray-400 text-sm">进度: {{ auditStore.currentTask.progress }}%</p>
        <div class="w-48 h-2 bg-[#161b22] rounded-full overflow-hidden mt-2 mx-auto">
          <div class="h-full bg-blue-500 rounded-full transition-all duration-500" :style="{ width: `${auditStore.currentTask?.progress ?? 0}%` }" />
        </div>
      </div>
    </div>

    <!-- Error State -->
    <div v-else-if="auditStore.currentTask?.status === 'failed'" class="flex items-center justify-center h-64">
      <div class="text-center">
        <svg class="w-12 h-12 mx-auto mb-3 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
        <p class="text-white font-medium mb-2">检测失败</p>
        <p class="text-gray-400 text-sm mb-4">{{ auditStore.error || '任务执行过程中发生错误' }}</p>
        <button
          v-if="auditStore.currentTask?.can_retry"
          @click="auditStore.fetchTask(taskId); /* retry */"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
        >
          重新检测
        </button>
      </div>
    </div>

    <!-- Main Content - Audit Result -->
    <template v-else-if="auditStore.currentReport">
      <!-- Top Cards -->
      <div class="px-4 pt-4">
        <TopCards />
      </div>

      <!-- Main Area: Editor + Right Panel -->
      <div class="flex-1 flex overflow-hidden min-h-0 px-4 py-4 gap-4">
        <!-- Center: Code Editor -->
        <div class="flex-1 min-w-0 bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden flex flex-col">
          <!-- Filter Checkboxes -->
          <div class="flex items-center gap-4 px-4 py-2 border-b border-[#30363d] bg-[#0d1117]/50 shrink-0 overflow-x-auto">
            <label class="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
              <input type="checkbox" checked class="accent-blue-500" /> 高亮显示
            </label>
            <label class="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
              <input type="checkbox" checked class="accent-green-500" /> 已验证
            </label>
            <label class="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
              <input type="checkbox" checked class="accent-orange-500" /> 疑似
            </label>
            <label class="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
              <input type="checkbox" checked class="accent-yellow-500" /> 预警
            </label>
            <label class="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
              <input type="checkbox" checked class="accent-purple-500" /> 未知异常
            </label>
          </div>
          <!-- Editor -->
          <div class="flex-1 min-h-0">
            <CodeEditor
              :findings="auditStore.currentReport.findings"
              :selected-finding="selectedFinding"
              @select-finding="handleFindingSelect"
            />
          </div>
        </div>

        <!-- Right Panel: Finding Detail -->
        <div class="w-80 shrink-0 overflow-hidden">
          <FindingDetailPanel
            :finding="selectedFinding"
            :report="auditStore.currentReport"
          />
        </div>
      </div>

      <!-- Bottom Panel -->
      <div class="border-t border-[#30363d] bg-[#0d1117] shrink-0">
        <!-- Tabs -->
        <div class="flex items-center border-b border-[#30363d] px-4">
          <button
            v-for="tab in bottomTabs"
            :key="tab.key"
            @click="activeBottomTab = tab.key"
            class="px-4 py-2.5 text-xs font-medium transition-colors border-b-2 -mb-px"
            :class="activeBottomTab === tab.key
              ? 'text-blue-400 border-blue-500'
              : 'text-gray-500 border-transparent hover:text-gray-300'"
          >
            {{ tab.label }}
          </button>
        </div>

        <!-- Panel Content -->
        <div class="h-56 overflow-y-auto">
          <TimelinePanel v-if="activeBottomTab === 'timeline'" :report="auditStore.currentReport" />
          <RiskRankingTable v-else-if="activeBottomTab === 'ranking'" :vectors="auditStore.top10RiskVectors" />
          <RadarChart v-else-if="activeBottomTab === 'radar'" :report="auditStore.currentReport" />
          <RiskWarningList v-else :warnings="auditStore.otherWarnings" />
        </div>
      </div>
    </template>

    <!-- No Report Yet -->
    <div v-else class="flex items-center justify-center h-64 text-gray-500">
      暂无审计数据，请先创建检测任务
    </div>
  </div>
</template>
