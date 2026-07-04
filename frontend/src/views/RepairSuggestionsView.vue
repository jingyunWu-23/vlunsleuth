<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import RepairSuggestions from '@/components/dashboard/RepairSuggestions.vue'

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

const findings = computed(() => auditStore.currentReport?.findings ?? [])

const repairableCount = computed(
  () =>
    findings.value.filter(
      (f) =>
        f.repair_suggestion &&
        (f.repair_suggestion.strategy ||
          f.repair_suggestion.patch_pattern ||
          (f.repair_suggestion.post_fix_checks && f.repair_suggestion.post_fix_checks.length > 0)),
    ).length,
)

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
        <h1 class="text-lg font-bold text-white">修复建议</h1>
        <p class="text-xs text-gray-500 mt-0.5">
          LLM 推理与验证智能体生成的代码修复方案
          <span v-if="repairableCount" class="text-green-400 ml-1">— {{ repairableCount }} 项可修复</span>
        </p>
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
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
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
      <RepairSuggestions :findings="findings" />
    </div>
  </div>
</template>
