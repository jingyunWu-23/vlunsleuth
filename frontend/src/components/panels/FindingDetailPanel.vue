<script setup lang="ts">
import { computed } from 'vue'
import type { Finding, AuditReport, VulnerabilityId, Severity } from '@/types'
import { VULN_LABELS, SEVERITY_COLORS } from '@/types'

const props = defineProps<{
  finding: Finding | null
  report: AuditReport | null
}>()

const vulnColor = (vid: VulnerabilityId): string => {
  switch (vid) {
    case 'VULN_REENTRANCY': return 'text-red-400 bg-red-500/10 border-red-500/30'
    case 'VULN_TIMESTAMP': return 'text-orange-400 bg-orange-500/10 border-orange-500/30'
    case 'VULN_DELEGATECALL': return 'text-purple-400 bg-purple-500/10 border-purple-500/30'
    case 'VULN_UNCHECKED_LOW_LEVEL_CALLS': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
    case 'VULN_CROSS_CONTRACT_RISK': return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
    case 'VULN_UNKNOWN_ANOMALY': return 'text-blue-400 bg-blue-500/10 border-blue-500/30'
  }
}

const severityBadge = (s: Severity) => SEVERITY_COLORS[s] ?? 'bg-gray-600 text-white'

const statusLabel = (s: string): string => {
  switch (s) {
    case 'confirmed': return '已验证'
    case 'suspected': return '疑似'
    case 'rejected': return '已排除'
    case 'inconclusive': return '待确认'
    default: return s
  }
}
</script>

<template>
  <div class="bg-[#161b22] border border-[#30363d] rounded-xl h-full overflow-y-auto">
    <div v-if="!finding" class="flex flex-col items-center justify-center h-full text-gray-500 p-6">
      <svg class="w-12 h-12 mb-3 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" />
      </svg>
    </div>

    <template v-else>
      <!-- Header -->
      <div class="p-4 border-b border-[#30363d]">
        <div class="flex items-center gap-2 mb-2">
          <span class="px-2 py-0.5 text-xs font-medium rounded border" :class="vulnColor(finding.vulnerability_id)">
            {{ VULN_LABELS[finding.vulnerability_id] }}
          </span>
          <span class="px-2 py-0.5 text-xs font-medium rounded" :class="severityBadge(finding.severity)">
            {{ finding.severity.toUpperCase() }}
          </span>
        </div>
        <h3 class="text-white text-sm font-medium leading-relaxed">{{ finding.summary }}</h3>

        <!-- Meta -->
        <div class="flex items-center gap-4 mt-3 text-xs text-gray-500">
          <span>
            {{ finding.contract_name }}.{{ finding.function_signature }}
          </span>
          <span>
            L{{ finding.location?.[0]?.start_line ?? '?' }}-{{ finding.location?.[0]?.end_line ?? '?' }}
          </span>
          <span class="px-2 py-0.5 rounded" :class="finding.status === 'confirmed' ? 'bg-green-500/10 text-green-400' : 'bg-orange-500/10 text-orange-400'">
            {{ statusLabel(finding.status) }}
          </span>
        </div>
      </div>

      <!-- Model Confidence Bars -->
      <div class="p-4 border-b border-[#30363d]">
        <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">模型置信度</h4>
        <div class="space-y-2.5">
          <div v-for="ev in finding.evidence" :key="ev.evidence_id">
            <div class="flex items-center justify-between text-xs mb-1">
              <span class="text-gray-400">{{ ev.model_id }}</span>
              <span class="text-gray-300 font-mono">{{ (ev.calibrated_confidence * 100).toFixed(0) }}%</span>
            </div>
            <div class="h-1.5 bg-[#0d1117] rounded-full overflow-hidden">
              <div
                class="h-full rounded-full transition-all"
                :class="{
                  'bg-green-500': ev.calibrated_confidence >= 0.85,
                  'bg-blue-500': ev.calibrated_confidence >= 0.7 && ev.calibrated_confidence < 0.85,
                  'bg-orange-500': ev.calibrated_confidence >= 0.5 && ev.calibrated_confidence < 0.7,
                  'bg-red-500': ev.calibrated_confidence < 0.5,
                }"
                :style="{ width: `${(ev.calibrated_confidence * 100).toFixed(0)}%` }"
              />
            </div>
          </div>
        </div>
      </div>

      <!-- Key Features -->
      <div v-if="finding.key_features?.length" class="p-4 border-b border-[#30363d]">
        <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">关键特征</h4>
        <ul class="space-y-2">
          <li v-for="(feat, i) in finding.key_features" :key="i" class="flex items-start gap-2 text-xs text-gray-300">
            <span class="text-blue-400 mt-0.5 shrink-0">&#9679;</span>
            {{ feat }}
          </li>
        </ul>
      </div>

      <!-- Attack Path -->
      <div v-if="finding.attack_path" class="p-4 border-b border-[#30363d]">
        <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">攻击路径</h4>
        <p class="text-xs text-gray-300 leading-relaxed">{{ finding.attack_path }}</p>
      </div>

      <!-- Verification -->
      <div v-if="finding.verification_plan" class="p-4 border-b border-[#30363d]">
        <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">验证结果</h4>
        <div v-if="finding.verification_plan.slither" class="mb-3">
          <div class="flex items-center gap-2 text-xs mb-1">
            <span class="text-gray-400">Slither:</span>
            <span :class="finding.verification_plan.slither.matched ? 'text-green-400' : 'text-red-400'">
              {{ finding.verification_plan.slither.matched ? '已匹配' : '未匹配' }}
            </span>
          </div>
          <p v-if="finding.verification_plan.slither.description" class="text-xs text-gray-500">
            {{ finding.verification_plan.slither.description }}
          </p>
        </div>
        <div v-if="finding.verification_plan.llm_verification">
          <div class="text-xs text-gray-400 mb-1">
            LLM 验证: <span class="text-blue-400">{{ finding.verification_plan.llm_verification.verdict }}</span>
            ({{ (finding.verification_plan.llm_verification.confidence * 100).toFixed(0) }}%)
          </div>
          <p class="text-xs text-gray-500">{{ finding.verification_plan.llm_verification.reasoning }}</p>
        </div>
      </div>

      <!-- Repair Suggestion -->
      <div v-if="finding.repair_suggestion" class="p-4">
        <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">修复建议</h4>
        <p v-if="finding.repair_suggestion.strategy" class="text-xs text-gray-300 mb-2">
          {{ finding.repair_suggestion.strategy }}
        </p>
        <pre v-if="finding.repair_suggestion.patch_pattern" class="text-xs text-green-400 bg-[#0d1117] p-2 rounded-lg overflow-x-auto font-mono">{{ finding.repair_suggestion.patch_pattern }}</pre>
        <ul v-if="finding.repair_suggestion.post_fix_checks?.length" class="mt-2 space-y-1">
          <li v-for="check in finding.repair_suggestion.post_fix_checks" :key="check" class="flex items-center gap-2 text-xs text-gray-400">
            <svg class="w-3.5 h-3.5 text-green-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
            </svg>
            {{ check }}
          </li>
        </ul>
      </div>
    </template>
  </div>
</template>
