<script setup lang="ts">
import { onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import FunctionRiskRanking from '@/components/dashboard/FunctionRiskRanking.vue'
import type { RiskVector } from '@/types'

const route = useRoute()
const router = useRouter()
const auditStore = useAuditStore()

const taskIdParam = route.query.task_id as string | undefined

onMounted(async () => {
  if (taskIdParam) {
    await auditStore.fetchTask(taskIdParam)
    if (auditStore.currentTask?.status === 'succeeded') {
      await auditStore.fetchReport(taskIdParam)
    }
  } else if (auditStore.currentTask && !auditStore.currentReport) {
    if (auditStore.currentTask.status === 'succeeded') {
      await auditStore.fetchReport(auditStore.currentTask.task_id)
    }
  }
})

function handleSelect(rv: RiskVector) {
  auditStore.selectRiskVector(rv)
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
        <h1 class="text-lg font-bold text-white">函数风险排名</h1>
        <p class="text-xs text-gray-500 mt-0.5">基于多维融合评分的函数级风险排序 — R_func 综合风险评估模型</p>
      </div>
      <div class="flex items-center gap-4">
        <span v-if="auditStore.currentTask" class="text-xs text-gray-500">
          当前任务:
          <span class="text-gray-300 font-mono">{{ auditStore.currentTask.task_id.slice(0, 16) }}...</span>
        </span>
        <button
          v-if="auditStore.currentTask"
          @click="goToAudit"
          class="px-3 py-1.5 text-xs bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 border border-blue-500/20 rounded-lg transition-colors"
        >
          查看审计详情 →
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

    <!-- No data -->
    <div v-else-if="!auditStore.currentReport" class="flex items-center justify-center flex-1">
      <div class="text-center">
        <svg class="w-14 h-14 mx-auto mb-3 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <p class="text-gray-500 text-sm mb-4">暂无审计数据</p>
        <button
          @click="router.push('/')"
          class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
        >
          创建审计任务
        </button>
      </div>
    </div>

    <!-- Content -->
    <div v-else class="flex-1 p-6 min-h-0">
      <FunctionRiskRanking
        :vectors="auditStore.currentReport.risk_vectors"
        @select="handleSelect"
      />
    </div>
  </div>
</template>
