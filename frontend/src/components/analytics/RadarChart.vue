<script setup lang="ts">
import { computed, ref, onMounted, watch } from 'vue'
import * as echarts from 'echarts'
import type { AuditReport, RiskVector } from '@/types'

const props = defineProps<{
  report: AuditReport | null
}>()

const chartRef = ref<HTMLDivElement>()
let chartInstance: echarts.ECharts | null = null

const dimensions = [
  { key: 'protection_score' as const, label: '安全防护', max: 1 },
  { key: 'business_score' as const, label: '业务敏感度', max: 1 },
  { key: 'consistency_score' as const, label: '一致性', max: 1 },
  { key: 'static_score' as const, label: '静态特征', max: 1 },
  { key: 'knowledge_score' as const, label: '知识库相似度', max: 1 },
  { key: 'anomaly_score' as const, label: 'DeepSVNN 异常', max: 1 },
]

const topVector = computed(() => {
  const vectors = props.report?.risk_vectors ?? []
  if (!vectors.length) return null
  return [...vectors].sort((a, b) => b.r_func - a.r_func)[0]
})

function buildOption(rv: RiskVector | null) {
  const indicator = dimensions.map((d) => ({
    name: d.label,
    max: d.max,
  }))

  const values = rv
    ? dimensions.map((d) => rv[d.key])
    : [0, 0, 0, 0, 0, 0]

  return {
    tooltip: {
      trigger: 'item' as const,
      backgroundColor: '#1c2128',
      borderColor: '#30363d',
      textStyle: { color: '#e6edf3', fontSize: 12 },
    },
    legend: {
      bottom: 0,
      textStyle: { color: '#8b949e', fontSize: 10 },
      data: rv ? [rv.function_signature] : [],
    },
    radar: {
      center: ['50%', '48%'],
      radius: '72%',
      indicator,
      axisName: {
        color: '#8b949e',
        fontSize: 10,
      },
      axisLine: { lineStyle: { color: '#30363d' } },
      splitLine: { lineStyle: { color: '#30363d' } },
      splitArea: {
        areaStyle: { color: ['rgba(88, 166, 255, 0.02)', 'rgba(88, 166, 255, 0.04)'] },
      },
    },
    series: [
      {
        type: 'radar' as const,
        data: [
          {
            value: values,
            name: rv?.function_signature ?? '无数据',
            areaStyle: { color: 'rgba(88, 166, 255, 0.15)' },
            lineStyle: { color: '#58a6ff', width: 2 },
            itemStyle: { color: '#58a6ff' },
          },
        ],
      },
    ],
  }
}

onMounted(() => {
  if (!chartRef.value) return
  chartInstance = echarts.init(chartRef.value, 'dark')
  chartInstance.setOption(buildOption(topVector.value))

  const observer = new ResizeObserver(() => {
    chartInstance?.resize()
  })
  observer.observe(chartRef.value)
})

watch(topVector, (rv) => {
  if (chartInstance && rv) {
    chartInstance.setOption(buildOption(rv), true)
  }
})
</script>

<template>
  <div class="p-4">
    <div class="text-xs text-gray-400 mb-2">
      展示函数:
      <span class="text-blue-400 font-mono">{{ topVector?.function_signature ?? '--' }}</span>
      <span class="text-gray-500 ml-2">
        (R_func: {{ topVector?.r_func?.toFixed(3) ?? '--' }})
      </span>
    </div>
    <div ref="chartRef" class="w-full h-40" />
  </div>
</template>
