<script setup lang="ts">
import type { RiskVector } from '@/types'

defineProps<{
  vectors: RiskVector[]
}>()

function riskLevel(r: number): { label: string; color: string } {
  if (r >= 0.7) return { label: '严重', color: 'bg-red-500/10 text-red-400 border-red-500/20' }
  if (r >= 0.45) return { label: '高', color: 'bg-orange-500/10 text-orange-400 border-orange-500/20' }
  if (r >= 0.35) return { label: '中', color: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' }
  return { label: '低', color: 'bg-green-500/10 text-green-400 border-green-500/20' }
}
</script>

<template>
  <div class="p-2">
    <table class="w-full text-xs">
      <thead>
        <tr class="border-b border-[#21262d] text-gray-500">
          <th class="text-left py-3 px-3 font-medium w-8">#</th>
          <th class="text-left py-3 px-3 font-medium">函数名</th>
          <th class="text-left py-3 px-3 font-medium">合约</th>
          <th class="text-right py-3 px-3 font-medium">R_func</th>
          <th class="text-right py-3 px-3 font-medium">等级</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="(rv, i) in vectors"
          :key="rv.function_id"
          class="border-b border-[#1a1f2b] hover:bg-[#1c2128] cursor-pointer transition-colors"
        >
          <td class="py-2.5 px-3 text-gray-600">{{ i + 1 }}</td>
          <td class="py-2.5 px-3">
            <span class="text-gray-200 font-mono">{{ rv.function_signature }}</span>
          </td>
          <td class="py-2.5 px-3 text-gray-400">{{ rv.contract_name }}</td>
          <td class="py-2.5 px-3 text-right font-mono">
            <span
              :class="{
                'text-red-400': rv.r_func >= 0.7,
                'text-orange-400': rv.r_func >= 0.45 && rv.r_func < 0.7,
                'text-yellow-400': rv.r_func >= 0.35 && rv.r_func < 0.45,
                'text-green-400': rv.r_func < 0.35,
              }"
            >
              {{ rv.r_func.toFixed(3) }}
            </span>
          </td>
          <td class="py-2.5 px-3 text-right">
            <span class="px-2 py-0.5 rounded text-xs border" :class="riskLevel(rv.r_func).color">
              {{ riskLevel(rv.r_func).label }}
            </span>
          </td>
        </tr>
        <tr v-if="!vectors.length">
          <td colspan="5" class="py-8 text-center text-gray-600">暂无风险排名数据</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
