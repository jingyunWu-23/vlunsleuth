<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, shallowRef } from 'vue'
import * as echarts from 'echarts'
import type { CallGraphData, CallGraphNode, CallGraphEdge } from '@/types'

const props = defineProps<{
  data: CallGraphData
}>()

const emit = defineEmits<{
  nodeClick: [node: CallGraphNode]
  edgeHover: [edge: CallGraphEdge]
}>()

const chartContainer = ref<HTMLDivElement>()
const chartInstance = shallowRef<echarts.ECharts | null>(null)
const showLegend = ref(true)
const selectedCategories = ref<string[]>(['contract', 'function'])

// --- Colors (dark theme palette) ---
const CATEGORY_COLORS: Record<string, string> = {
  contract_high: '#f85149',
  contract_medium: '#d2991d',
  contract_low: '#e3b341',
  contract_none: '#3fb950',
  function_high: '#ff7b72',
  function_medium: '#e09b2d',
  function_low: '#edd458',
  function_none: '#56d364',
}

function nodeCategory(n: CallGraphNode): string {
  return `${n.category}_${n.riskLevel}`
}

// --- ECharts Option Builder ---
function buildOption(data: CallGraphData): echarts.EChartsOption {
  const filteredNodes = data.nodes.filter((n) => selectedCategories.value.includes(n.category))
  const filteredNodeIds = new Set(filteredNodes.map((n) => n.id))
  const filteredEdges = data.edges.filter(
    (e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target),
  )

  // Categories for legend
  const categories = [
    { name: 'Contract (高风险)', itemStyle: { color: CATEGORY_COLORS.contract_high } },
    { name: 'Contract (安全)', itemStyle: { color: CATEGORY_COLORS.contract_none } },
    { name: 'Function (高风险)', itemStyle: { color: CATEGORY_COLORS.function_high } },
    { name: 'Function (正常)', itemStyle: { color: CATEGORY_COLORS.function_none } },
    { name: '风险边', itemStyle: { color: '#f85149' } },
    { name: '内部调用', itemStyle: { color: '#30363d' } },
  ]

  const nodes = filteredNodes.map((n) => ({
    id: n.id,
    name: n.name,
    symbolSize: n.symbolSize,
    category: getCategoryIndex(n),
    itemStyle: { color: CATEGORY_COLORS[nodeCategory(n)] },
    label: {
      show: n.category === 'contract' || n.riskLevel !== 'none',
      fontSize: n.category === 'contract' ? 11 : 9,
      color: '#c9d1d9',
      formatter: n.name.length > 18 ? n.name.slice(0, 16) + '..' : n.name,
    },
    tooltip: {
      formatter: () => buildNodeTooltip(n),
    },
    // Custom data preserved for tooltips and click handlers
    _raw: n,
  }))

  const edges = filteredEdges.map((e) => ({
    source: e.source,
    target: e.target,
    lineStyle: {
      color: e.riskFlag ? '#f85149' : '#30363d',
      width: e.riskFlag ? 2 : 1,
      curveness: 0.15,
      type: e.callType === 'internal' ? 'dashed' : 'solid',
    },
    label: {
      show: e.riskFlag,
      formatter: e.methodName ?? '',
      fontSize: 8,
      color: '#8b949e',
    },
    tooltip: {
      formatter: () => buildEdgeTooltip(e),
    },
    _raw: e,
  }))

  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item' as const,
      backgroundColor: '#161b22',
      borderColor: '#30363d',
      textStyle: { color: '#e6edf3', fontSize: 12 },
      extraCssText: 'border-radius: 8px; padding: 10px 14px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);',
    },
    legend: showLegend.value
      ? {
          show: true,
          top: 8,
          left: 8,
          orient: 'horizontal',
          itemWidth: 12,
          itemHeight: 12,
          itemGap: 16,
          textStyle: { color: '#8b949e', fontSize: 10 },
          data: categories.map((c) => c.name),
        }
      : { show: false },
    series: [
      {
        type: 'graph',
        layout: 'force',
        roam: true,
        draggable: true,
        cursor: 'grab',
        animation: true,
        animationDuration: 800,
        animationEasingUpdate: 'cubicInOut',
        categories: categories.map((c, i) => ({ name: c.name, itemStyle: { color: c.itemStyle.color } })),

        force: {
          initIterations: 300,
          repulsion: 350,
          gravity: 0.08,
          edgeLength: [80, 250],
          layoutAnimation: true,
          friction: 0.6,
        },

        emphasis: {
          focus: 'adjacency',
          lineStyle: { width: 3 },
          itemStyle: { shadowBlur: 16, shadowColor: 'rgba(88, 166, 255, 0.6)' },
        },

        // Edge with arrow
        edgeSymbol: ['none', 'arrow'],
        edgeSymbolSize: [0, 8],

        // Scale limits
        scaleLimit: {
          min: 0.3,
          max: 4,
        },

        data: nodes,
        edges: edges,
      } as echarts.SeriesOption,
    ],
  }
}

function getCategoryIndex(n: CallGraphNode): number {
  if (n.category === 'contract') {
    return n.riskLevel === 'high' || n.riskLevel === 'medium' ? 0 : 1
  }
  return n.riskLevel === 'high' || n.riskLevel === 'medium' ? 2 : 3
}

function buildNodeTooltip(n: CallGraphNode): string {
  const riskLabel =
    n.riskLevel === 'high'
      ? '<span style="color:#f85149">&#9679; 高风险</span>'
      : n.riskLevel === 'medium'
        ? '<span style="color:#d2991d">&#9679; 中风险</span>'
        : n.riskLevel === 'low'
          ? '<span style="color:#e3b341">&#9679; 低风险</span>'
          : '<span style="color:#3fb950">&#9679; 安全</span>'

  return [
    `<div style="font-weight:600;font-size:13px;margin-bottom:4px">${n.name}</div>`,
    `<div style="color:#8b949e;font-size:11px">${n.category === 'contract' ? '合约' : '函数'}  ·  ${n.contractName}</div>`,
    `<div style="margin-top:6px">${riskLabel}</div>`,
    n.crossContractFindings > 0
      ? `<div style="color:#f85149;font-size:11px;margin-top:2px">跨合约风险发现: ${n.crossContractFindings}</div>`
      : '',
    n.rFunc !== undefined
      ? `<div style="color:#8b949e;font-size:11px;margin-top:2px">R_func: ${n.rFunc.toFixed(3)}</div>`
      : '',
  ].join('')
}

function buildEdgeTooltip(e: CallGraphEdge): string {
  return [
    `<div style="font-weight:600;font-size:12px;margin-bottom:4px">${e.callType === 'external' ? '外部调用 (跨合约)' : '内部调用'}</div>`,
    e.methodName
      ? `<div style="color:#8b949e;font-size:11px">方法: <span style="color:#58a6ff;font-family:monospace">${e.methodName}</span></div>`
      : '',
    e.riskFlag
      ? `<div style="color:#f85149;font-size:11px;margin-top:2px">&#9888; 标记为跨合约风险</div>`
      : '',
  ].join('')
}

// --- Init & Lifecycle ---
let resizeObserver: ResizeObserver | null = null

onMounted(() => {
  if (!chartContainer.value) return

  chartInstance.value = echarts.init(chartContainer.value, 'dark', {
    devicePixelRatio: window.devicePixelRatio || 1,
  })

  chartInstance.value.setOption(buildOption(props.data))

  // Click handler → emit node click
  chartInstance.value.on('click', (params: { data?: { _raw?: CallGraphNode } }) => {
    if (params.data?._raw) {
      emit('nodeClick', params.data._raw)
    }
  })

  // Mouseover on edge → emit edge hover
  chartInstance.value.on('mouseover', (params: { dataType?: string; data?: { _raw?: CallGraphEdge } }) => {
    if (params.dataType === 'edge' && params.data?._raw) {
      emit('edgeHover', params.data._raw)
    }
  })

  resizeObserver = new ResizeObserver(() => {
    chartInstance.value?.resize()
  })
  resizeObserver.observe(chartContainer.value)
})

onUnmounted(() => {
  resizeObserver?.disconnect()
  chartInstance.value?.dispose()
  chartInstance.value = null
})

watch(
  () => props.data,
  (newData) => {
    if (chartInstance.value) {
      chartInstance.value.setOption(buildOption(newData), true)
    }
  },
  { deep: true },
)

watch(selectedCategories, () => {
  if (chartInstance.value) {
    chartInstance.value.setOption(buildOption(props.data), true)
  }
})

// --- Public methods (exposed to parent) ---
function resetView() {
  chartInstance.value?.dispatchAction({
    type: 'restore',
  })
}

function toggleFilter(category: string) {
  const idx = selectedCategories.value.indexOf(category)
  if (idx >= 0) {
    if (selectedCategories.value.length > 1) {
      selectedCategories.value = selectedCategories.value.filter((c) => c !== category)
    }
  } else {
    selectedCategories.value = [...selectedCategories.value, category]
  }
}

defineExpose({ resetView, toggleFilter })
</script>

<template>
  <div class="relative w-full h-full bg-[#0d1117] rounded-xl border border-[#30363d] overflow-hidden flex flex-col">
    <!-- Toolbar -->
    <div class="flex items-center justify-between px-4 py-2 border-b border-[#30363d] bg-[#0d1117]/80 shrink-0">
      <div class="flex items-center gap-3">
        <!-- Filter pills -->
        <button
          v-for="f in [
            { key: 'contract', label: '合约节点', dot: 'bg-green-500' },
            { key: 'function', label: '函数节点', dot: 'bg-blue-400' },
          ]"
          :key="f.key"
          @click="toggleFilter(f.key)"
          class="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full border transition-colors"
          :class="
            selectedCategories.includes(f.key)
              ? 'bg-blue-600/20 border-blue-500/30 text-blue-400'
              : 'bg-transparent border-[#30363d] text-gray-500 hover:border-[#484f58]'
          "
        >
          <span class="w-1.5 h-1.5 rounded-full" :class="f.dot" />
          {{ f.label }}
        </button>
        <div class="w-px h-4 bg-[#30363d]" />
        <button
          @click="showLegend = !showLegend"
          class="flex items-center gap-1 text-xs transition-colors"
          :class="showLegend ? 'text-gray-300' : 'text-gray-600'"
        >
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
          </svg>
          图例
        </button>
      </div>

      <!-- Reset button -->
      <button
        @click="resetView"
        class="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-[#1c2128] hover:bg-[#2d333b] text-gray-300 rounded-lg border border-[#30363d] transition-colors"
      >
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        重置视图
      </button>
    </div>

    <!-- Chart -->
    <div ref="chartContainer" class="flex-1 w-full" />

    <!-- Empty state -->
    <div
      v-if="!data.nodes.length"
      class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none"
    >
      <svg class="w-16 h-16 text-gray-700 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
      </svg>
      <p class="text-gray-600 text-sm">暂无调用图数据</p>
      <p class="text-gray-700 text-xs mt-1">完成审计任务后自动生成</p>
    </div>
  </div>
</template>
