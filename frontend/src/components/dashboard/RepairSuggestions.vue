<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import type { Finding, VulnerabilityId, Severity } from '@/types'
import { VULN_LABELS } from '@/types'
import MonacoDiffEditor from '@/components/editor/MonacoDiffEditor.vue'
import MonacoCodeViewer from '@/components/editor/MonacoCodeViewer.vue'

const props = defineProps<{
  findings: Finding[]
}>()

// --- Internal selected finding ---
const selectedId = ref<string | null>(null)
const viewMode = ref<'diff' | 'fixed' | 'original'>('diff')
const copied = ref(false)

// Findings that have repair suggestions
const repairableFindings = computed(() =>
  props.findings.filter(
    (f) =>
      f.repair_suggestion &&
      (f.repair_suggestion.strategy ||
        f.repair_suggestion.patch_pattern ||
        (f.repair_suggestion.post_fix_checks && f.repair_suggestion.post_fix_checks.length > 0)),
  ),
)

// Selected value
const selectedFinding = computed<Finding | null>(() => {
  if (selectedId.value) return props.findings.find((f) => f.finding_id === selectedId.value) ?? null
  return repairableFindings.value[0] ?? null
})

// Resolve original code: from repair_suggestion.original_snippet, or evidence snippet
const originalCode = computed(() => {
  const f = selectedFinding.value
  if (!f?.repair_suggestion) return ''
  if (f.repair_suggestion.original_snippet) return f.repair_suggestion.original_snippet
  // Fallback: build from evidence location snippets
  const snippets = f.evidence
    .flatMap((e) => e.location_candidates?.map((l) => l.snippet) ?? [])
    .filter(Boolean)
  return snippets.join('\n') || generateMockOriginal(f)
})

const patchedCode = computed(() => {
  return selectedFinding.value?.repair_suggestion?.patch_pattern ?? ''
})

// Viewable code (for single-editor fallback when no original)
const viewableCode = computed(() => {
  const f = selectedFinding.value
  if (!f?.repair_suggestion) return ''
  if (viewMode.value === 'fixed') return f.repair_suggestion.patch_pattern ?? ''
  if (viewMode.value === 'original') return originalCode.value
  // diff mode
  return ''
})

const hasDiff = computed(() => !!originalCode.value && !!patchedCode.value)

// --- Vuln styling helpers ---
function vulnColor(vid: VulnerabilityId): string {
  const map: Record<VulnerabilityId, string> = {
    VULN_REENTRANCY: 'text-red-400 bg-red-500/10 border-red-500/30',
    VULN_TIMESTAMP: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    VULN_DELEGATECALL: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
    VULN_UNCHECKED_LOW_LEVEL_CALLS: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    VULN_CROSS_CONTRACT_RISK: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    VULN_UNKNOWN_ANOMALY: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  }
  return map[vid]
}

function severityBadge(s: Severity): string {
  const map: Record<Severity, string> = {
    high: 'bg-red-600 text-white',
    medium: 'bg-orange-500 text-white',
    low: 'bg-yellow-500 text-black',
  }
  return map[s]
}

function statusLabel(s: string): string {
  const map: Record<string, string> = {
    confirmed: '已验证',
    suspected: '疑似',
    rejected: '已排除',
    inconclusive: '待确认',
  }
  return map[s] ?? s
}

// --- Actions ---
function selectFinding(f: Finding) {
  selectedId.value = f.finding_id
}

watch(selectedFinding, () => {
  // Auto-switch to best view mode
  if (originalCode.value && patchedCode.value) {
    viewMode.value = 'diff'
  } else if (patchedCode.value) {
    viewMode.value = 'fixed'
  } else if (originalCode.value) {
    viewMode.value = 'original'
  }
})

async function copyPatchCode() {
  const code = patchedCode.value
  if (!code) return
  try {
    await navigator.clipboard.writeText(code)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    // fallback
    const ta = document.createElement('textarea')
    ta.value = code
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  }
}

// --- Mock original code generator (fallback when no snippet available) ---
function generateMockOriginal(f: Finding): string {
  if (!f.repair_suggestion?.patch_pattern) return ''
  // Produce a naive "before" by adding common vulnerability patterns
  const vuln = f.vulnerability_id
  if (vuln === 'VULN_REENTRANCY') {
    return `// 原始代码 - 存在重入漏洞
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;  // 状态更新在外部调用之后
}`
  }
  if (vuln === 'VULN_UNCHECKED_LOW_LEVEL_CALLS') {
    return `// 原始代码 - 未检查低级调用返回值
function transfer(address to, uint256 amount) external {
    msg.sender.call{value: amount}("");
    // 未检查 call() 返回值
}`
  }
  if (vuln === 'VULN_DELEGATECALL') {
    return `// 原始代码 - 不安全的 delegatecall
function execute(address target, bytes memory data) external {
    target.delegatecall(data);  // 未验证目标地址
}`
  }
  if (vuln === 'VULN_TIMESTAMP') {
    return `// 原始代码 - 时间戳依赖
function random() external view returns (uint256) {
    return uint256(keccak256(abi.encodePacked(block.timestamp)));
}`
  }
  return `// 原始漏洞代码\n${f.function_signature}`
}
</script>

<template>
  <div class="flex gap-4 h-full min-h-0">
    <!-- ====== LEFT: Finding List ====== -->
    <div class="w-[380px] shrink-0 flex flex-col bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
      <div class="px-5 py-3 border-b border-[#30363d] shrink-0">
        <h3 class="text-sm font-semibold text-white">可修复漏洞</h3>
        <p class="text-xs text-gray-500 mt-0.5">
          共 {{ repairableFindings.length }} 项有修复建议
        </p>
      </div>

      <div
        v-if="!repairableFindings.length"
        class="flex flex-col items-center justify-center flex-1 text-gray-600 p-4"
      >
        <svg class="w-12 h-12 mb-3 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p class="text-sm text-center">暂无修复建议</p>
        <p class="text-xs mt-1">当前审计任务未生成修复方案</p>
      </div>

      <div v-else class="flex-1 overflow-y-auto">
        <button
          v-for="f in repairableFindings"
          :key="f.finding_id"
          @click="selectFinding(f)"
          class="w-full text-left px-4 py-3 border-b border-[#1a1f2b] transition-colors group"
          :class="
            selectedId === f.finding_id || (!selectedId && f === repairableFindings[0])
              ? 'bg-blue-600/15 border-l-2 border-l-blue-500'
              : 'border-l-2 border-l-transparent hover:bg-[#1c2128]'
          "
        >
          <div class="flex items-center gap-2 mb-1.5">
            <span class="px-2 py-0.5 text-xs rounded border" :class="vulnColor(f.vulnerability_id)">
              {{ VULN_LABELS[f.vulnerability_id] }}
            </span>
            <span class="px-1.5 py-0.5 text-xs rounded" :class="severityBadge(f.severity)">
              {{ f.severity.toUpperCase() }}
            </span>
            <span class="text-xs text-gray-600 ml-auto">
              {{ statusLabel(f.status) }}
            </span>
          </div>
          <div class="text-sm text-gray-200 font-medium truncate">
            {{ f.contract_name }}.{{ f.function_signature }}
          </div>
          <p class="text-xs text-gray-500 mt-1 truncate">
            {{ f.repair_suggestion?.strategy || '修复方案可用' }}
          </p>
        </button>
      </div>
    </div>

    <!-- ====== RIGHT: Detail Panel ====== -->
    <div class="flex-1 flex flex-col min-w-0 gap-4 overflow-y-auto">
      <!-- Empty state -->
      <div
        v-if="!selectedFinding"
        class="flex-1 flex items-center justify-center bg-[#161b22] border border-[#30363d] rounded-xl"
      >
        <div class="text-center text-gray-500">
          <svg class="w-14 h-14 mx-auto mb-3 text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
          </svg>
          <p class="text-sm">选择左侧漏洞查看修复建议</p>
        </div>
      </div>

      <template v-else>
        <!-- Header card -->
        <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-5 shrink-0">
          <div class="flex items-start justify-between">
            <div>
              <div class="flex items-center gap-2 mb-2">
                <span class="px-2 py-0.5 text-xs rounded border" :class="vulnColor(selectedFinding.vulnerability_id)">
                  {{ VULN_LABELS[selectedFinding.vulnerability_id] }}
                </span>
                <span class="px-1.5 py-0.5 text-xs rounded" :class="severityBadge(selectedFinding.severity)">
                  {{ selectedFinding.severity.toUpperCase() }}
                </span>
              </div>
              <h2 class="text-base font-bold text-white">
                {{ selectedFinding.contract_name }}.{{ selectedFinding.function_signature }}
              </h2>
              <p class="text-sm text-gray-400 mt-1.5 leading-relaxed">{{ selectedFinding.summary }}</p>
            </div>
            <button
              @click="copyPatchCode"
              :disabled="!patchedCode"
              class="flex items-center gap-1.5 px-3 py-2 text-xs rounded-lg border transition-colors shrink-0 ml-4"
              :class="
                copied
                  ? 'bg-green-600/20 border-green-500/30 text-green-400'
                  : 'bg-[#0d1117] border-[#30363d] text-gray-300 hover:border-[#484f58] hover:text-white'
              "
            >
              <svg v-if="!copied" class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              <svg v-else class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              {{ copied ? '已复制' : '复制补丁代码' }}
            </button>
          </div>
        </div>

        <!-- Strategy -->
        <div
          v-if="selectedFinding.repair_suggestion?.strategy"
          class="bg-[#161b22] border border-[#30363d] rounded-xl p-5 shrink-0"
        >
          <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">修复策略</h3>
          <div class="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
            {{ selectedFinding.repair_suggestion.strategy }}
          </div>
        </div>

        <!-- Code Diff -->
        <div
          v-if="patchedCode || originalCode"
          class="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden flex flex-col shrink-0"
        >
          <div class="flex items-center justify-between px-5 py-3 border-b border-[#30363d]">
            <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">
              {{ hasDiff ? '代码对比 Diff' : '修复代码' }}
            </h3>
            <!-- View mode tabs -->
            <div v-if="hasDiff" class="flex items-center gap-1">
              <button
                v-for="mode in [
                  { key: 'diff' as const, label: '差异对比' },
                  { key: 'fixed' as const, label: '修复后' },
                  { key: 'original' as const, label: '原始代码' },
                ]"
                :key="mode.key"
                @click="viewMode = mode.key"
                class="px-2.5 py-1 text-xs rounded transition-colors"
                :class="
                  viewMode === mode.key
                    ? 'bg-blue-600/20 text-blue-400'
                    : 'text-gray-500 hover:text-gray-300'
                "
              >
                {{ mode.label }}
              </button>
            </div>
          </div>

          <div class="min-h-[350px]" :class="{ 'h-[420px]': hasDiff && viewMode === 'diff' }">
            <!-- Diff mode -->
            <MonacoDiffEditor
              v-if="hasDiff && viewMode === 'diff'"
              :original="originalCode"
              :modified="patchedCode"
              language="sol"
              :read-only="true"
              class="w-full h-full"
            />
            <!-- Single editor (fixed/original only) -->
            <div v-else-if="viewMode !== 'diff' && viewableCode" class="w-full h-[350px]">
              <MonacoCodeViewer :code="viewableCode" language="sol" />
            </div>
            <div v-else class="flex items-center justify-center h-32 text-gray-600 text-sm">
              无可对比的代码
            </div>
          </div>
        </div>

        <!-- Post-fix Checks -->
        <div
          v-if="selectedFinding.repair_suggestion?.post_fix_checks?.length"
          class="bg-[#161b22] border border-[#30363d] rounded-xl p-5 shrink-0"
        >
          <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">
            修复后安全检查清单
          </h3>
          <div class="space-y-3">
            <div
              v-for="(check, i) in selectedFinding.repair_suggestion.post_fix_checks"
              :key="i"
              class="flex items-start gap-3 p-3 bg-[#0d1117] border border-[#21262d] rounded-lg"
            >
              <div class="w-5 h-5 rounded-full bg-green-500/15 border border-green-500/30 flex items-center justify-center shrink-0 mt-0.5">
                <svg class="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <span class="text-sm text-gray-300 leading-relaxed">{{ check }}</span>
            </div>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>
