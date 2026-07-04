<script setup lang="ts">
import type { RiskVector } from '@/types'

const props = defineProps<{
  vectors: RiskVector[]
}>()

function riskLevel(r: number): { label: string; color: string; bg: string } {
  if (r >= 0.7) return { label: '严重', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' }
  if (r >= 0.45) return { label: '高',  color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' }
  if (r >= 0.35) return { label: '中',  color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' }
  return { label: '低', color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20' }
}

function scoreColor(r: number): string {
  if (r >= 0.7) return 'text-red-400'
  if (r >= 0.45) return 'text-orange-400'
  if (r >= 0.35) return 'text-yellow-400'
  return 'text-green-400'
}

function barColor(r: number): string {
  if (r >= 0.7) return 'bg-red-500'
  if (r >= 0.45) return 'bg-orange-500'
  if (r >= 0.35) return 'bg-yellow-500'
  return 'bg-green-500'
}

const averageScore = props.vectors.length
  ? (props.vectors.reduce((s, v) => s + v.r_func, 0) / props.vectors.length)
  : 0
</script>

<template>
  <div class="p-6 h-full flex flex-col">
    <!-- Header -->
    <div class="flex items-center justify-between mb-5 shrink-0">
      <div>
        <h3 class="text-base font-semibold text-white">函数风险排名 TOP 10</h3>
        <p class="text-xs text-gray-500 mt-1">按 R_func 多维融合风险分降序排列</p>
      </div>
      <div class="flex items-center gap-4 text-xs text-gray-500">
        <span>平均分: <span class="text-gray-300 font-mono">{{ averageScore.toFixed(3) }}</span></span>
        <span>总计: <span class="text-gray-300">{{ vectors.length }}</span> 个函数</span>
      </div>
    </div>

    <!-- Table -->
    <div v-if="vectors.length" class="flex-1 overflow-y-auto bg-[#161b22] border border-[#21262d] rounded-xl">
      <table class="w-full text-xs">
        <thead class="sticky top-0 z-10 bg-[#161b22]">
          <tr class="border-b border-[#21262d] text-gray-500">
            <th class="text-left py-3 px-5 font-medium w-10">#</th>
            <th class="text-left py-3 px-3 font-medium">函数签名</th>
            <th class="text-left py-3 px-3 font-medium w-40">所属合约</th>
            <th class="text-right py-3 px-3 font-medium w-20">异常分</th>
            <th class="text-right py-3 px-3 font-medium w-20">GCN 分</th>
            <th class="text-right py-3 px-3 font-medium w-20">静态分</th>
            <th class="text-right py-3 px-3 font-medium w-20">业务敏感度</th>
            <th class="text-right py-3 px-3 font-medium w-28">R_func</th>
            <th class="text-right py-3 px-5 font-medium w-16">等级</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(rv, i) in vectors.slice(0, 10)"
            :key="rv.function_id"
            class="border-b border-[#1a1f2b] hover:bg-[#1c2128] transition-colors"
          >
            <!-- Rank -->
            <td class="py-3 px-5">
              <span
                class="w-6 h-6 rounded-lg flex items-center justify-center text-xs font-bold"
                :class="{
                  'bg-red-500/15 text-red-400': i === 0,
                  'bg-orange-500/10 text-orange-400': i === 1,
                  'bg-yellow-500/10 text-yellow-400': i === 2,
                  'bg-[#0d1117] text-gray-600': i > 2,
                }"
              >
                {{ i + 1 }}
              </span>
            </td>

            <!-- Function signature -->
            <td class="py-3 px-3">
              <div class="text-gray-200 font-mono text-xs truncate max-w-[280px]" :title="rv.function_signature">
                {{ rv.function_signature }}
              </div>
            </td>

            <!-- Contract -->
            <td class="py-3 px-3 text-gray-400 truncate max-w-[140px]" :title="rv.contract_name">
              {{ rv.contract_name }}
            </td>

            <!-- Anomaly -->
            <td class="py-3 px-3 text-right font-mono" :class="scoreColor(rv.anomaly_score)">
              {{ rv.anomaly_score.toFixed(3) }}
            </td>

            <!-- GCN -->
            <td class="py-3 px-3 text-right font-mono" :class="scoreColor(rv.gcn_score)">
              {{ rv.gcn_score.toFixed(3) }}
            </td>

            <!-- Static -->
            <td class="py-3 px-3 text-right font-mono" :class="scoreColor(rv.static_score)">
              {{ rv.static_score.toFixed(3) }}
            </td>

            <!-- Business -->
            <td class="py-3 px-3 text-right font-mono" :class="scoreColor(rv.business_score)">
              {{ rv.business_score.toFixed(3) }}
            </td>

            <!-- R_func with bar -->
            <td class="py-3 px-3 text-right">
              <div class="flex items-center gap-2.5 justify-end">
                <div class="w-20 h-1.5 bg-[#0d1117] rounded-full overflow-hidden">
                  <div
                    class="h-full rounded-full transition-all"
                    :class="barColor(rv.r_func)"
                    :style="{ width: `${Math.min(rv.r_func * 100, 100)}%` }"
                  />
                </div>
                <span class="font-mono font-medium w-14 text-right" :class="scoreColor(rv.r_func)">
                  {{ rv.r_func.toFixed(2) }}
                </span>
              </div>
            </td>

            <!-- Level Badge -->
            <td class="py-3 px-5 text-right">
              <span class="px-2.5 py-1 rounded text-xs border font-medium" :class="riskLevel(rv.r_func).bg + ' ' + riskLevel(rv.r_func).color">
                {{ riskLevel(rv.r_func).label }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Empty -->
    <div v-else class="flex-1 flex items-center justify-center bg-[#161b22] border border-[#21262d] rounded-xl">
      <div class="text-center text-gray-600">
        <svg class="w-10 h-10 mx-auto mb-2 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 4h13M3 8h9m-9 4h9m5-4v12m0 0l-4-4m4 4l4-4" />
        </svg>
        <p class="text-sm">暂无风险排名数据</p>
      </div>
    </div>
  </div>
</template>
