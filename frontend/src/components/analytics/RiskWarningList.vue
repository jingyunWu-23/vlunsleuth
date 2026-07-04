<script setup lang="ts">
import type { Warning } from '@/types'
import { VULN_LABELS } from '@/types'

defineProps<{
  warnings: Warning[]
}>()

function warningColor(status: string): string {
  switch (status) {
    case 'screening_warning': return 'border-yellow-500/30 bg-yellow-500/5'
    case 'rejected_false_positive': return 'border-gray-500/30 bg-gray-500/5'
    case 'anomaly_warning': return 'border-purple-500/30 bg-purple-500/5'
    default: return 'border-[#30363d]'
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case 'screening_warning': return '筛查预警'
    case 'rejected_false_positive': return '误报排除'
    case 'anomaly_warning': return '异常预警'
    default: return status
  }
}
</script>

<template>
  <div class="p-2 space-y-2">
    <div
      v-for="w in warnings"
      :key="w.warning_id"
      class="flex items-start gap-3 p-3 rounded-lg border transition-colors hover:border-[#484f58]"
      :class="warningColor(w.status)"
    >
      <!-- Icon -->
      <div class="w-8 h-8 rounded-lg shrink-0 flex items-center justify-center"
        :class="{
          'bg-yellow-500/10 text-yellow-400': w.status === 'screening_warning',
          'bg-gray-500/10 text-gray-400': w.status === 'rejected_false_positive',
          'bg-purple-500/10 text-purple-400': w.status === 'anomaly_warning',
        }"
      >
        <svg v-if="w.status === 'screening_warning'" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
        <svg v-else-if="w.status === 'rejected_false_positive'" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636l-12.728 12.728M5.636 5.636l12.728 12.728" />
        </svg>
        <svg v-else class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      </div>

      <!-- Content -->
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2 mb-1">
          <span class="text-xs text-gray-300 font-medium truncate">
            {{ w.contract_name }}.{{ w.function_signature }}
          </span>
          <span class="text-xs px-1.5 py-0.5 rounded bg-[#0d1117] text-gray-500 shrink-0">
            {{ VULN_LABELS[w.target_vulnerability] ?? w.target_vulnerability }}
          </span>
        </div>
        <p class="text-xs text-gray-400 leading-relaxed">{{ w.summary }}</p>
        <div v-if="w.recommended_action" class="flex items-center gap-2 mt-1.5">
          <span class="text-xs text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded">
            {{ w.recommended_action.action }}
          </span>
        </div>
      </div>

      <!-- Score -->
      <div class="text-xs font-mono shrink-0 pt-1"
        :class="{
          'text-yellow-400': w.score >= 0.5,
          'text-gray-400': w.score < 0.5,
        }"
      >
        {{ w.score.toFixed(2) }}
      </div>
    </div>

    <div v-if="!warnings.length" class="text-center py-8 text-gray-600 text-sm">
      暂无其他风险项
    </div>
  </div>
</template>
