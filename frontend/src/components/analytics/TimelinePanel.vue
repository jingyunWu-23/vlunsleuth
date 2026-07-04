<script setup lang="ts">
import type { AuditReport } from '@/types'

defineProps<{
  report: AuditReport | null
}>()

// Mock timeline — in production this comes from task events API
const steps = [
  { id: 1, label: '合约预处理', desc: 'Solidity解析 · 特征提取 · 字节码编译', duration: '2.3s', status: 'done' },
  { id: 2, label: 'LSTM 检测', desc: '4类已知漏洞扫描 (Reentrancy/Timestamp/Delegatecall/UncheckedCall)', duration: '4.1s', status: 'done' },
  { id: 3, label: 'GCN 检测', desc: '跨合约调用图风险分析', duration: '3.8s', status: 'done' },
  { id: 4, label: 'DeepSVNN 检测', desc: '异常行为检测 (行为偏离度)', duration: '5.2s', status: 'done' },
  { id: 5, label: '函数风险评分', desc: 'R_func 多维融合评分 + RAG 知识匹配', duration: '1.5s', status: 'done' },
  { id: 6, label: '推理定位', desc: 'LLM 推理筛选高价值函数生成发现 (DeepSeek v4-pro)', duration: '8.6s', status: 'done' },
  { id: 7, label: '漏洞验证', desc: 'Slither 验证 + LLM 验证智能体', duration: '3.2s', status: 'done' },
  { id: 8, label: '修复建议', desc: '生成修复策略、补丁模式及验证检查项', duration: '1.1s', status: 'done' },
]
</script>

<template>
  <div class="p-4">
    <div class="relative">
      <!-- Vertical line -->
      <div class="absolute left-4 top-2 bottom-2 w-0.5 bg-[#30363d]" />

      <div class="space-y-3">
        <div v-for="step in steps" :key="step.id" class="flex items-start gap-4 relative">
          <!-- Node -->
          <div
            class="relative z-10 w-4 h-4 rounded-full border-2 shrink-0 mt-0.5"
            :class="step.status === 'done' ? 'bg-green-500 border-green-500' : 'bg-[#161b22] border-[#30363d]'"
          >
            <svg v-if="step.status === 'done'" class="w-2.5 h-2.5 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-white" fill="currentColor" viewBox="0 0 24 24">
              <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" />
            </svg>
          </div>

          <!-- Content -->
          <div class="flex-1 min-w-0">
            <div class="flex items-center justify-between">
              <span class="text-xs font-medium text-gray-200">{{ step.label }}</span>
              <span class="text-xs text-gray-600 font-mono">{{ step.duration }}</span>
            </div>
            <p class="text-xs text-gray-500 mt-0.5">{{ step.desc }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
