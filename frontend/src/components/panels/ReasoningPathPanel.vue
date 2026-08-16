<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import type { AuditReport, ModelEvidence, ReasoningVerificationPlan, VulnerabilityId } from '@/types'
import { VULN_LABELS, SEVERITY_COLORS, SEVERITY_LABELS } from '@/types'

const props = defineProps<{
  report: AuditReport | null
}>()

const selectedIndex = ref(0)

const orderedFindings = computed(() => {
  const all = props.report?.findings ?? []
  const reasoned = all.filter((f) => f.reasoning)
  const source = reasoned.length ? reasoned : all
  return [...source].sort(
    (a, b) =>
      severityOrder(b.severity) - severityOrder(a.severity) ||
      (b.confidence ?? 0) - (a.confidence ?? 0),
  )
})

const selectedFinding = computed(() => orderedFindings.value[selectedIndex.value] ?? null)

const gate = computed(() => props.report?.metadata?.reasoning_gate ?? null)

watch(
  () => props.report?.task_id,
  () => {
    selectedIndex.value = 0
  },
)

function severityOrder(severity: string) {
  return severity === 'high' ? 3 : severity === 'medium' ? 2 : severity === 'low' ? 1 : 0
}

function shortFunctionId(fid: string) {
  const idx = fid.lastIndexOf(':')
  return idx >= 0 ? fid.slice(idx + 1) : fid
}

function modelLabel(modelId: string) {
  if (modelId.startsWith('LSTM')) return 'LSTM 模型'
  if (modelId.startsWith('GCN')) return 'GCN 模型'
  if (modelId.startsWith('DEEPSVDD')) return 'DeepSVDD 模型'
  if (modelId.startsWith('STATIC')) return '静态规则引擎'
  return modelId
}

function statusLabel(status?: string) {
  switch (status) {
    case 'confirmed':
      return '已验证'
    case 'suspected':
      return '疑似'
    case 'rejected':
      return '已排除'
    case 'inconclusive':
      return '待确认'
    default:
      return status || '--'
  }
}

function vulnColor(vid: VulnerabilityId): string {
  switch (vid) {
    case 'VULN_REENTRANCY': return 'text-red-400 bg-red-500/10 border-red-500/30'
    case 'VULN_TIMESTAMP': return 'text-orange-400 bg-orange-500/10 border-orange-500/30'
    case 'VULN_DELEGATECALL': return 'text-purple-400 bg-purple-500/10 border-purple-500/30'
    case 'VULN_UNCHECKED_LOW_LEVEL_CALLS': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
    case 'VULN_ACCESS_CONTROL': return 'text-pink-400 bg-pink-500/10 border-pink-500/30'
    case 'VULN_ARITHMETIC': return 'text-amber-400 bg-amber-500/10 border-amber-500/30'
    case 'VULN_BAD_RANDOMNESS': return 'text-lime-400 bg-lime-500/10 border-lime-500/30'
    case 'VULN_LOCKED_ETHER': return 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30'
    case 'VULN_CROSS_CONTRACT_RISK': return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
    case 'VULN_UNKNOWN_ANOMALY': return 'text-blue-400 bg-blue-500/10 border-blue-500/30'
    case 'VULN_LLM_SEMANTIC_WARNING': return 'text-purple-400 bg-purple-500/10 border-purple-500/30'
  }
}

const locations = computed(() => selectedFinding.value?.reasoning?.location ?? [])

const verificationPlan = computed<ReasoningVerificationPlan | null>(() => {
  const vp = selectedFinding.value?.verification_plan as
    | { goal?: unknown; static_checks?: unknown; dynamic_checks?: unknown }
    | undefined
  if (vp && typeof vp.goal === 'string') {
    return {
      goal: vp.goal,
      static_checks: Array.isArray(vp.static_checks) ? (vp.static_checks as string[]) : undefined,
      dynamic_checks: Array.isArray(vp.dynamic_checks) ? (vp.dynamic_checks as string[]) : undefined,
    }
  }
  return selectedFinding.value?.reasoning?.verification_plan ?? null
})

const verificationResult = computed(() => {
  const vp = selectedFinding.value?.verification_plan as Record<string, unknown> | undefined
  if (vp && ('slither' in vp || 'llm_verification' in vp)) return vp
  return null
})

const repairSuggestion = computed(
  () => selectedFinding.value?.repair_suggestion ?? selectedFinding.value?.reasoning?.repair_suggestion ?? null,
)

const knowledgeItems = computed(() => (selectedFinding.value?.knowledge ?? []) as Record<string, unknown>[])

function knowledgeTitle(item: Record<string, unknown>) {
  return String(item.vulnerability_name ?? item.knowledge_type ?? item.swc_id ?? item.knowledge_id ?? '知识条目')
}

function dangerousApis(ev: ModelEvidence): string[] {
  const apis = (ev.feature_evidence ?? []).flatMap((f) => {
    const features = (f as Record<string, unknown>).features as Record<string, unknown> | undefined
    const list = features?.dangerous_apis
    return Array.isArray(list) ? (list as string[]) : []
  })
  return [...new Set(apis)]
}

interface CriticalStatement {
  line?: number
  code?: string
  roles?: string[]
}

function criticalStatements(ev: ModelEvidence): CriticalStatement[] {
  return (ev.feature_evidence ?? []).flatMap((f) => {
    const features = (f as Record<string, unknown>).features as Record<string, unknown> | undefined
    const list = features?.critical_statements
    return Array.isArray(list) ? (list as CriticalStatement[]) : []
  })
}
</script>

<template>
  <div class="flex h-full">
    <!-- 左侧：推理定位概览 + 漏洞列表 -->
    <div class="w-80 shrink-0 border-r border-[#30363d] overflow-y-auto">
      <div v-if="gate" class="p-4 border-b border-[#30363d]">
        <div class="text-xs text-gray-500 mb-2">推理定位概览</div>
        <div class="flex items-baseline gap-2 mb-3">
          <span class="text-blue-400 text-lg font-semibold">{{ gate.selected_count }}</span>
          <span class="text-xs text-gray-400">/ {{ gate.max_candidates }} 个高价值函数入选 LLM 推理</span>
        </div>
        <div class="max-h-44 overflow-y-auto space-y-2">
          <div v-for="fid in gate.selected_function_ids" :key="fid" class="text-[11px]">
            <div class="text-gray-300 font-mono truncate">{{ shortFunctionId(fid) }}</div>
            <div class="flex flex-wrap gap-1 mt-0.5">
              <span
                v-for="reason in gate.reasons?.[fid] ?? []"
                :key="reason"
                class="px-1.5 py-0.5 rounded bg-[#0d1117] border border-[#21262d] text-gray-500"
              >
                {{ reason }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div
        v-if="!orderedFindings.length"
        class="flex items-center justify-center h-40 text-xs text-gray-600"
      >
        暂无推理定位数据
      </div>

      <button
        v-for="(finding, i) in orderedFindings"
        :key="finding.finding_id"
        @click="selectedIndex = i"
        class="w-full text-left px-4 py-3 border-b border-[#1a1f2b] transition-colors border-l-2"
        :class="
          selectedIndex === i
            ? 'bg-blue-600/10 border-l-blue-500'
            : 'border-l-transparent hover:bg-[#1c2128]'
        "
      >
        <div class="flex items-center gap-2 mb-1">
          <span class="px-1.5 py-0.5 text-[10px] rounded border" :class="vulnColor(finding.vulnerability_id)">
            {{ VULN_LABELS[finding.vulnerability_id] }}
          </span>
          <span class="px-1.5 py-0.5 text-[10px] rounded" :class="SEVERITY_COLORS[finding.severity]">
            {{ SEVERITY_LABELS[finding.severity] }}
          </span>
        </div>
        <div class="text-xs text-gray-300 font-mono truncate">
          {{ finding.contract_name }}.{{ finding.function_signature }}
        </div>
        <div class="text-[11px] text-gray-500 mt-0.5">
          {{ statusLabel(finding.status) }} · 置信度 {{ ((finding.confidence ?? 0) * 100).toFixed(0) }}%
        </div>
      </button>
    </div>

    <!-- 右侧：推理路径详情 -->
    <div class="flex-1 overflow-y-auto">
      <div v-if="!selectedFinding" class="flex items-center justify-center h-full text-gray-600 text-sm">
        请选择左侧漏洞查看推理路径
      </div>

      <div v-else class="p-5 space-y-5">
        <!-- 头部 -->
        <div class="flex items-start justify-between gap-4">
          <div>
            <div class="flex items-center gap-2 mb-2">
              <span class="px-2 py-0.5 text-xs font-medium rounded border" :class="vulnColor(selectedFinding.vulnerability_id)">
                {{ VULN_LABELS[selectedFinding.vulnerability_id] }}
              </span>
              <span class="px-2 py-0.5 text-xs font-medium rounded" :class="SEVERITY_COLORS[selectedFinding.severity]">
                {{ SEVERITY_LABELS[selectedFinding.severity] }}
              </span>
              <span class="text-xs text-gray-500">{{ statusLabel(selectedFinding.status) }}</span>
            </div>
            <h3 class="text-sm font-medium text-white leading-relaxed">{{ selectedFinding.summary }}</h3>
            <div class="text-xs text-gray-500 font-mono mt-2">
              {{ selectedFinding.contract_name }}.{{ selectedFinding.function_signature }}
            </div>
          </div>
          <div class="shrink-0 text-right">
            <div class="text-2xl font-semibold text-blue-400">
              {{ ((selectedFinding.confidence ?? 0) * 100).toFixed(0) }}%
            </div>
            <div class="text-[11px] text-gray-500">置信度</div>
            <div
              v-if="selectedFinding.reasoning?.confidence_adjustment != null"
              class="text-[11px] mt-1"
              :class="(selectedFinding.reasoning.confidence_adjustment ?? 0) >= 0 ? 'text-green-400' : 'text-red-400'"
            >
              调整 {{ (selectedFinding.reasoning.confidence_adjustment ?? 0) >= 0 ? '+' : ''
              }}{{ selectedFinding.reasoning.confidence_adjustment }}
            </div>
          </div>
        </div>

        <!-- LLM 推理链 -->
        <section v-if="selectedFinding.reasoning?.reasoning?.length">
          <h4 class="text-xs font-medium text-gray-400 mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            LLM 推理链
          </h4>
          <ol class="space-y-2">
            <li
              v-for="(step, i) in selectedFinding.reasoning.reasoning"
              :key="i"
              class="flex gap-3 text-xs leading-relaxed"
            >
              <span class="shrink-0 w-5 h-5 rounded-full bg-blue-500/15 text-blue-400 border border-blue-500/30 flex items-center justify-center text-[10px] font-semibold">
                {{ i + 1 }}
              </span>
              <span class="text-gray-300 pt-0.5">{{ step }}</span>
            </li>
          </ol>
        </section>

        <!-- 关键代码定位 -->
        <section v-if="locations.length">
          <h4 class="text-xs font-medium text-gray-400 mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
              <path stroke-linecap="round" stroke-linejoin="round" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            关键代码定位
          </h4>
          <div class="space-y-2">
            <div
              v-for="(loc, i) in locations"
              :key="i"
              class="rounded-lg border border-[#30363d] bg-[#161b22] overflow-hidden"
            >
              <div class="flex items-center gap-2 px-3 py-1.5 border-b border-[#21262d]">
                <span class="text-[11px] text-gray-500">
                  第 {{ loc.line ?? `${loc.start_line}-${loc.end_line}` }} 行
                </span>
                <span v-if="loc.reason" class="text-[11px] text-orange-400/80 flex-1 truncate">{{ loc.reason }}</span>
              </div>
              <pre v-if="loc.code" class="px-3 py-2 text-xs font-mono text-gray-300 overflow-x-auto">{{ loc.code }}</pre>
            </div>
          </div>
        </section>

        <!-- 多模型证据链 -->
        <section v-if="selectedFinding.evidence?.length">
          <h4 class="text-xs font-medium text-gray-400 mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
            </svg>
            多模型证据链
          </h4>
          <div class="space-y-2">
            <div
              v-for="ev in selectedFinding.evidence"
              :key="ev.evidence_id"
              class="rounded-lg border border-[#30363d] bg-[#161b22] p-3"
            >
              <div class="flex items-center justify-between mb-1.5">
                <span class="text-xs font-medium text-gray-200">{{ modelLabel(ev.model_id) }}</span>
                <span class="text-[11px] text-gray-500 font-mono">{{ ev.model_id }}</span>
              </div>
              <div class="flex items-center gap-4 text-[11px] text-gray-500 mb-1.5">
                <span>原始分 {{ (ev.raw_score ?? 0).toFixed(3) }}</span>
                <span>校准置信度 {{ ((ev.calibrated_confidence ?? 0) * 100).toFixed(0) }}%</span>
                <span v-if="ev.label" class="text-blue-400">{{ ev.label }}</span>
              </div>
              <div v-if="dangerousApis(ev).length" class="flex items-center gap-1.5 flex-wrap">
                <span class="text-[11px] text-gray-500">危险 API:</span>
                <span
                  v-for="api in dangerousApis(ev)"
                  :key="api"
                  class="px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-[10px] font-mono"
                >
                  {{ api }}
                </span>
              </div>
              <div v-if="criticalStatements(ev).length" class="mt-1.5 space-y-1">
                <div
                  v-for="(stmt, i) in criticalStatements(ev)"
                  :key="i"
                  class="flex items-center gap-2 text-[11px]"
                >
                  <span class="text-gray-600 font-mono shrink-0">L{{ stmt.line }}</span>
                  <code class="text-gray-400 font-mono truncate">{{ stmt.code }}</code>
                  <span v-if="stmt.roles?.length" class="text-gray-600 shrink-0">
                    [{{ stmt.roles.join(', ') }}]
                  </span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- RAG 知识库匹配 -->
        <section v-if="knowledgeItems.length">
          <h4 class="text-xs font-medium text-gray-400 mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
            </svg>
            RAG 知识库匹配
          </h4>
          <div class="space-y-2">
            <div
              v-for="(item, i) in knowledgeItems"
              :key="i"
              class="rounded-lg border border-[#30363d] bg-[#161b22] p-3"
            >
              <div class="flex items-center gap-2 mb-1">
                <span class="text-xs font-medium text-gray-200">{{ knowledgeTitle(item) }}</span>
                <span v-if="item.swc_id" class="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-400 font-mono">
                  {{ item.swc_id }}
                </span>
                <span v-if="item.risk_level" class="text-[10px] text-gray-500">{{ item.risk_level }}</span>
              </div>
              <p v-if="item.content" class="text-[11px] text-gray-500 leading-relaxed line-clamp-3">
                {{ item.content }}
              </p>
            </div>
          </div>
        </section>

        <!-- 验证计划 -->
        <section v-if="verificationPlan">
          <h4 class="text-xs font-medium text-gray-400 mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            验证计划
          </h4>
          <div class="rounded-lg border border-[#30363d] bg-[#161b22] p-3 space-y-2">
            <p v-if="verificationPlan.goal" class="text-xs text-gray-300 leading-relaxed">{{ verificationPlan.goal }}</p>
            <div v-if="verificationPlan.static_checks?.length">
              <div class="text-[11px] text-gray-500 mb-1">静态检查</div>
              <ul class="space-y-1">
                <li v-for="(check, i) in verificationPlan.static_checks" :key="i" class="text-xs text-gray-400 flex gap-2">
                  <span class="text-gray-600">·</span>{{ check }}
                </li>
              </ul>
            </div>
            <div v-if="verificationPlan.dynamic_checks?.length">
              <div class="text-[11px] text-gray-500 mb-1">动态检查</div>
              <ul class="space-y-1">
                <li v-for="(check, i) in verificationPlan.dynamic_checks" :key="i" class="text-xs text-gray-400 flex gap-2">
                  <span class="text-gray-600">·</span>{{ check }}
                </li>
              </ul>
            </div>
          </div>
        </section>

        <!-- 验证结果 -->
        <section v-if="verificationResult">
          <h4 class="text-xs font-medium text-gray-400 mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            验证结果
          </h4>
          <div class="rounded-lg border border-[#30363d] bg-[#161b22] p-3 space-y-2">
            <template v-if="verificationResult.slither">
              <div class="flex items-center gap-2">
                <span
                  class="px-1.5 py-0.5 rounded text-[10px]"
                  :class="(verificationResult.slither as Record<string, unknown>).matched
                    ? 'bg-green-500/15 text-green-400 border border-green-500/30'
                    : 'bg-red-500/15 text-red-400 border border-red-500/30'"
                >
                  Slither {{ (verificationResult.slither as Record<string, unknown>).matched ? '命中' : '未命中' }}
                </span>
                <span v-if="(verificationResult.slither as Record<string, unknown>).detector" class="text-xs text-gray-400 font-mono">
                  {{ (verificationResult.slither as Record<string, unknown>).detector }}
                </span>
              </div>
              <p v-if="(verificationResult.slither as Record<string, unknown>).description" class="text-xs text-gray-500 leading-relaxed">
                {{ (verificationResult.slither as Record<string, unknown>).description }}
              </p>
            </template>
            <template v-if="verificationResult.llm_verification">
              <div class="flex items-center gap-2">
                <span class="text-xs text-gray-200">LLM 复核: {{ (verificationResult.llm_verification as Record<string, unknown>).verdict }}</span>
                <span class="text-[11px] text-gray-500">
                  置信度 {{ (((verificationResult.llm_verification as Record<string, unknown>).confidence as number ?? 0) * 100).toFixed(0) }}%
                </span>
              </div>
              <p v-if="(verificationResult.llm_verification as Record<string, unknown>).reasoning" class="text-xs text-gray-500 leading-relaxed">
                {{ (verificationResult.llm_verification as Record<string, unknown>).reasoning }}
              </p>
            </template>
          </div>
        </section>

        <!-- 修复建议 -->
        <section v-if="repairSuggestion">
          <h4 class="text-xs font-medium text-gray-400 mb-2 flex items-center gap-1.5">
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
            </svg>
            修复建议
          </h4>
          <div class="rounded-lg border border-[#30363d] bg-[#161b22] p-3 space-y-2">
            <p v-if="repairSuggestion.strategy" class="text-xs text-gray-300 leading-relaxed">{{ repairSuggestion.strategy }}</p>
            <pre v-if="repairSuggestion.patch_pattern" class="px-3 py-2 rounded bg-[#0d1117] border border-[#21262d] text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap">{{ repairSuggestion.patch_pattern }}</pre>
            <div v-if="repairSuggestion.post_fix_checks?.length">
              <div class="text-[11px] text-gray-500 mb-1">修复后检查</div>
              <ul class="space-y-1">
                <li v-for="(check, i) in repairSuggestion.post_fix_checks" :key="i" class="text-xs text-gray-400 flex gap-2">
                  <span class="text-gray-600">·</span>{{ check }}
                </li>
              </ul>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>
