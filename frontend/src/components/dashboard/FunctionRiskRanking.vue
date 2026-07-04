<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, shallowRef, nextTick } from 'vue'
import * as echarts from 'echarts'
import type { RiskVector, Severity } from '@/types'

const props = defineProps<{
  vectors: RiskVector[]
}>()

const emit = defineEmits<{
  select: [rv: RiskVector]
}>()

// --- State ---
const selectedId = ref<string | null>(null)
const sortKey = ref<'r_func' | 'anomaly_score' | 'gcn_score' | 'static_score' | 'business_score' | 'knowledge_score' | 'consistency_score'>('r_func')
const sortDir = ref<-1 | 1>(-1)
const chartRef = ref<HTMLDivElement>()
let chartInstance: echarts.ECharts | null = null
let resizeObserver: ResizeObserver | null = null

// --- Dimension definitions (matching the R_func formula) ---
interface DimDef {
  key: keyof RiskVector
  label: string
  symbol: string
  weight: number
  weightSign: '+' | '-'
  color: string
}

const dimensions: DimDef[] = [
  { key: 'anomaly_score',      label: '异常分 (Aₐ)',        symbol: 'Aₐ', weight: 0.25, weightSign: '+', color: '#f85149' },
  { key: 'gcn_score',          label: 'GCN分 (Gₐ)',        symbol: 'Gₐ', weight: 0.15, weightSign: '+', color: '#a371f7' },
  { key: 'static_score',       label: '静态分 (Sₐ)',        symbol: 'Sₐ', weight: 0.20, weightSign: '+', color: '#d2991d' },
  { key: 'business_score',     label: '业务敏感度 (Bₐ)',    symbol: 'Bₐ', weight: 0.15, weightSign: '+', color: '#3fb950' },
  { key: 'knowledge_score',    label: '知识库匹配 (Kₐ)',    symbol: 'Kₐ', weight: 0.15, weightSign: '+', color: '#39d2c0' },
  { key: 'consistency_score',  label: '多源一致性 (Cₐ)',    symbol: 'Cₐ', weight: 0.10, weightSign: '+', color: '#58a6ff' },
]

// Secondary dimension shown outside the radar
const protectionDim: DimDef = {
  key: 'protection_score', label: '安全防护 (Pₐ)', symbol: 'Pₐ', weight: 0.20, weightSign: '-', color: '#8b949e',
}

// --- Sorted vectors ---
const sortedVectors = computed(() => {
  const arr = [...props.vectors]
  arr.sort((a, b) => {
    const va = a[sortKey.value] as number
    const vb = b[sortKey.value] as number
    return (va - vb) * sortDir.value
  })
  return arr
})

const top10 = computed(() => sortedVectors.value.slice(0, 10))

// --- Selected vector ---
const selectedVector = computed<RiskVector | null>(() => {
  if (selectedId.value) {
    return props.vectors.find((v) => v.function_id === selectedId.value) ?? null
  }
  // default to top ranked
  return sortedVectors.value[0] ?? null
})

// --- Risk level helpers ---
function riskLevel(r: number): { label: string; color: string; bg: string } {
  if (r >= 0.7) return { label: '严重', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' }
  if (r >= 0.45) return { label: '高',  color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' }
  if (r >= 0.35) return { label: '中',  color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' }
  return { label: '低', color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20' }
}

function severityFromRFunc(r: number): Severity {
  if (r >= 0.7) return 'high'
  if (r >= 0.45) return 'medium'
  return 'low'
}

// --- Computed formula value ---
const formulaBreakdown = computed(() => {
  const v = selectedVector.value
  if (!v) return null
  const positiveSum = dimensions.reduce((s, d) => s + (v[d.key] as number) * d.weight, 0)
  const protectionTerm = (v.protection_score as number) * protectionDim.weight
  return { positiveSum, protectionTerm, rFunc: positiveSum - protectionTerm }
})

// --- ECharts ---
function buildRadarOption(rv: RiskVector | null) {
  const indicator = dimensions.map((d) => ({
    name: d.label,
    max: 1,
  }))

  const values = rv ? dimensions.map((d) => rv[d.key] as number) : [0, 0, 0, 0, 0, 0]

  // Build 6 individual dimension rings for the "petals" effect
  const seriesData = dimensions.map((d, i) => {
    const fullValues = new Array(6).fill(0)
    fullValues[i] = values[i]
    return {
      value: fullValues,
      name: d.label,
    }
  })

  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item' as const,
      backgroundColor: '#161b22',
      borderColor: '#30363d',
      textStyle: { color: '#e6edf3', fontSize: 12 },
      formatter: (params: { name?: string; value?: number[]; color?: string }) => {
        if (!params.value || !params.name) return ''
        const idx = dimensions.findIndex((d) => d.label === params.name)
        if (idx < 0) return ''
        const d = dimensions[idx]
        const raw = values[idx]
        const contrib = raw * d.weight
        return [
          `<div style="font-weight:600;font-size:13px;margin-bottom:4px;color:${d.color}">${d.label}</div>`,
          `<div style="color:#8b949e;font-size:11px">原始分数: <span style="color:#e6edf3;font-family:monospace">${(raw * 100).toFixed(1)}%</span></div>`,
          `<div style="color:#8b949e;font-size:11px">权重: <span style="color:#e6edf3">${d.weightSign}${d.weight.toFixed(2)}</span></div>`,
          `<div style="color:#8b949e;font-size:11px">加权贡献: <span style="color:${d.color};font-family:monospace">${d.weightSign}${contrib.toFixed(4)}</span></div>`,
        ].join('')
      },
    },
    legend: {
      bottom: 2,
      textStyle: { color: '#6e7681', fontSize: 9 },
      itemWidth: 8,
      itemHeight: 8,
      itemGap: 10,
    },
    radar: {
      center: ['50%', '46%'],
      radius: '68%',
      indicator: indicator.map((ind, i) => ({
        ...ind,
        color: dimensions[i].color,
      })),
      axisName: {
        color: '#8b949e',
        fontSize: 9,
        formatter: (label: string) => {
          const d = dimensions.find((dd) => dd.label === label)
          return d ? d.symbol : label.length > 5 ? label.slice(0, 4) + '..' : label
        },
      },
      axisLine: { lineStyle: { color: '#21262d' } },
      splitLine: { lineStyle: { color: '#21262d' } },
      splitArea: {
        areaStyle: {
          color: [
            'rgba(88, 166, 255, 0.03)',
            'rgba(88, 166, 255, 0.07)',
          ],
        },
      },
    },
    series: dimensions.map((d, i) => ({
      type: 'radar' as const,
      name: d.symbol,
      symbol: 'none' as const,
      lineStyle: { color: d.color, width: 1.5, type: 'solid' as const },
      areaStyle: { color: d.color + '20' },
      itemStyle: { color: d.color },
      data: [
        {
          value: seriesData[i].value,
          name: d.symbol,
        },
      ],
      emphasis: {
        lineStyle: { width: 2.5 },
        areaStyle: { color: d.color + '40' },
      },
    })),
  }
}

onMounted(() => {
  if (!chartRef.value) return
  chartInstance = echarts.init(chartRef.value, 'dark', {
    devicePixelRatio: window.devicePixelRatio || 1,
  })
  chartInstance.setOption(buildRadarOption(selectedVector.value))

  resizeObserver = new ResizeObserver(() => {
    chartInstance?.resize()
  })
  resizeObserver.observe(chartRef.value)
})

onUnmounted(() => {
  resizeObserver?.disconnect()
  chartInstance?.dispose()
  chartInstance = null
})

watch(selectedVector, (rv) => {
  if (chartInstance && rv) {
    chartInstance.setOption(buildRadarOption(rv), true)
  }
})

// --- Actions ---
function selectRow(rv: RiskVector) {
  selectedId.value = rv.function_id
  emit('select', rv)
}

function toggleSort(key: typeof sortKey.value) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === -1 ? 1 : -1
  } else {
    sortKey.value = key
    sortDir.value = -1
  }
}

function resetView() {
  chartInstance?.dispatchAction({ type: 'restore' })
}

defineExpose({ resetView })
</script>

<template>
  <div class="flex gap-4 h-full min-h-0">
    <!-- ====== LEFT: Table Panel ====== -->
    <div class="w-[460px] shrink-0 flex flex-col bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
      <!-- Header -->
      <div class="px-5 py-3 border-b border-[#30363d] shrink-0">
        <h3 class="text-sm font-semibold text-white">函数风险排名 TOP 10</h3>
        <p class="text-xs text-gray-500 mt-0.5">按 R_func 综合风险分降序排列</p>
      </div>

      <!-- R_func formula banner -->
      <div class="px-5 py-2.5 border-b border-[#30363d] bg-[#0d1117]/60 shrink-0">
        <div class="text-xs text-gray-500 mb-1">综合风险分公式</div>
        <div class="flex flex-wrap items-center gap-x-1 gap-y-0.5 font-mono text-xs">
          <span class="text-white">R_func</span>
          <span class="text-gray-600">=</span>
          <template v-for="(d, i) in dimensions" :key="d.key">
            <span v-if="i > 0" class="text-gray-600">+</span>
            <span :style="{ color: d.color }">{{ d.weight.toFixed(2) }}&times;{{ d.symbol }}</span>
          </template>
          <span class="text-gray-600">-</span>
          <span class="text-gray-500">{{ protectionDim.weight.toFixed(2) }}&times;{{ protectionDim.symbol }}</span>
        </div>
      </div>

      <!-- Table -->
      <div class="flex-1 overflow-y-auto">
        <table class="w-full text-xs">
          <thead class="sticky top-0 z-10 bg-[#161b22]">
            <tr class="border-b border-[#21262d] text-gray-500">
              <th class="text-left py-2.5 px-4 font-medium w-8">#</th>
              <th class="text-left py-2.5 px-3 font-medium cursor-pointer hover:text-gray-300 select-none" @click="toggleSort('r_func')">
                函数名
                <span v-if="sortKey === 'r_func'" class="ml-1 text-blue-400">{{ sortDir === -1 ? '↓' : '↑' }}</span>
              </th>
              <th class="text-left py-2.5 px-3 font-medium w-24">合约</th>
              <th class="text-right py-2.5 px-3 font-medium w-20 cursor-pointer hover:text-gray-300 select-none" @click="toggleSort('r_func')">
                R_func
                <span v-if="sortKey === 'r_func'" class="ml-1 text-blue-400">{{ sortDir === -1 ? '↓' : '↑' }}</span>
              </th>
              <th class="text-right py-2.5 px-4 font-medium w-16">等级</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(rv, i) in top10"
              :key="rv.function_id"
              @click="selectRow(rv)"
              class="border-b border-[#1a1f2b] cursor-pointer transition-colors"
              :class="selectedId === rv.function_id
                ? 'bg-blue-600/15 border-l-2 border-l-blue-500'
                : 'hover:bg-[#1c2128] border-l-2 border-l-transparent'"
            >
              <td class="py-2.5 px-4 text-gray-600 font-mono">{{ i + 1 }}</td>
              <td class="py-2.5 px-3">
                <div class="text-gray-200 font-mono truncate max-w-[180px]" :title="rv.function_signature">
                  {{ rv.function_signature }}
                </div>
              </td>
              <td class="py-2.5 px-3 text-gray-500 truncate max-w-[90px]" :title="rv.contract_name">
                {{ rv.contract_name }}
              </td>
              <td class="py-2.5 px-3 text-right font-mono">
                <span
                  :class="{
                    'text-red-400 font-semibold': rv.r_func >= 0.7,
                    'text-orange-400': rv.r_func >= 0.45 && rv.r_func < 0.7,
                    'text-yellow-400': rv.r_func >= 0.35 && rv.r_func < 0.45,
                    'text-green-400': rv.r_func < 0.35,
                  }"
                >
                  {{ rv.r_func.toFixed(2) }}
                </span>
              </td>
              <td class="py-2.5 px-4 text-right">
                <span class="px-2 py-0.5 rounded text-xs border" :class="riskLevel(rv.r_func).bg + ' ' + riskLevel(rv.r_func).color">
                  {{ riskLevel(rv.r_func).label }}
                </span>
              </td>
            </tr>
            <tr v-if="!top10.length">
              <td colspan="5" class="py-12 text-center text-gray-600">
                <svg class="w-8 h-8 mx-auto mb-2 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                暂无风险排名数据
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- ====== RIGHT: Radar + Breakdown ====== -->
    <div class="flex-1 flex flex-col gap-4 min-w-0">
      <!-- Radar Chart -->
      <div class="flex-1 bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden flex flex-col min-h-0">
        <div class="flex items-center justify-between px-5 py-3 border-b border-[#30363d] shrink-0">
          <div>
            <h3 class="text-sm font-semibold text-white">
              风险分数组成
              <span v-if="selectedVector" class="text-gray-500 font-normal ml-2 font-mono text-xs">
                {{ selectedVector.function_signature }}
              </span>
            </h3>
          </div>
          <button
            @click="resetView"
            class="flex items-center gap-1 px-2.5 py-1 text-xs bg-[#0d1117] hover:bg-[#1c2128] text-gray-400 rounded-lg border border-[#30363d] transition-colors"
          >
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            重置
          </button>
        </div>
        <div ref="chartRef" class="flex-1 w-full" />
      </div>

      <!-- R_func Breakdown Card -->
      <div v-if="formulaBreakdown" class="bg-[#161b22] border border-[#30363d] rounded-xl p-5 shrink-0">
        <h4 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">R_func 计算明细</h4>

        <div class="grid grid-cols-3 gap-x-8 gap-y-2 text-xs">
          <div v-for="d in dimensions" :key="d.key" class="flex items-center justify-between">
            <span class="text-gray-500">{{ d.symbol }}</span>
            <span class="font-mono text-gray-300">{{ (selectedVector?.[d.key] as number)?.toFixed(3) ?? '--' }}</span>
            <span class="font-mono text-gray-500">
              {{ d.weightSign }}{{ ((selectedVector?.[d.key] as number ?? 0) * d.weight).toFixed(4) }}
            </span>
          </div>
          <div class="flex items-center justify-between border-t border-[#21262d] pt-2 mt-1">
            <span class="text-gray-500">Pₐ (防护)</span>
            <span class="font-mono text-gray-300">{{ (selectedVector?.protection_score as number)?.toFixed(3) ?? '--' }}</span>
            <span class="font-mono text-red-400">
              -{{ ((selectedVector?.protection_score as number ?? 0) * protectionDim.weight).toFixed(4) }}
            </span>
          </div>
        </div>

        <div class="flex items-center gap-3 mt-3 pt-3 border-t border-[#21262d]">
          <div class="flex-1 text-right text-xs">
            <span class="text-gray-500">正向加权和</span>
            <span class="text-gray-300 font-mono ml-2">{{ formulaBreakdown.positiveSum.toFixed(4) }}</span>
          </div>
          <span class="text-gray-600">-</span>
          <div class="text-xs">
            <span class="text-gray-500">防护偏移</span>
            <span class="text-gray-300 font-mono ml-2">{{ formulaBreakdown.protectionTerm.toFixed(4) }}</span>
          </div>
          <span class="text-gray-600">=</span>
          <div class="text-sm font-bold" :class="riskLevel(formulaBreakdown.rFunc).color">
            {{ formulaBreakdown.rFunc.toFixed(2) }}
          </div>
        </div>
      </div>

      <div v-else class="bg-[#161b22] border border-[#30363d] rounded-xl p-5 shrink-0 text-center text-gray-600 text-xs">
        点击左侧表格中的函数以查看 R_func 计算明细
      </div>
    </div>
  </div>
</template>
