<script setup lang="ts">
import type { AuditReport } from '@/types'

defineProps<{
  report: AuditReport | null
}>()

type StepStatus = 'done' | 'running' | 'pending'

interface Step {
  id: number
  label: string
  desc: string
  duration: string
  status: StepStatus
  modelIcon: string
}

const steps: Step[] = [
  { id: 1, label: '合约预处理',   desc: 'Solidity 源码解析、AST 提取、合约/函数/调用图构建、静态特征提取与字节码编译', duration: '2.3s',  status: 'done',    modelIcon: 'M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6z' },
  { id: 2, label: 'LSTM 专项检测', desc: '4 类已知漏洞模型推理：重入漏洞 | 时间戳依赖 | 不安全 delegatecall | 未检查低级调用返回值',  duration: '4.1s',  status: 'done',    modelIcon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
  { id: 3, label: 'DeepSVNN 异常检测', desc: '深度 SVDD 异常行为偏离度分析，识别合约行为的异常模式', duration: '5.2s', status: 'done', modelIcon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' },
  { id: 4, label: 'GCN 跨合约分析', desc: '图卷积网络跨合约调用图风险检测，分析合约间调用拓扑结构与异常调用模式', duration: '3.8s', status: 'done', modelIcon: 'M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7' },
  { id: 5, label: '静态规则引擎', desc: '基于预定义安全规则的静态分析，检测危险 API 调用、状态更新模式及防护措施', duration: '0.8s',  status: 'done',    modelIcon: 'M4 7v10c0 2 1 3 3 3h10c2 0 3-1 3-3V7M4 7c0-2 1-3 3-3h10c2 0 3 1 3 3M4 7h16' },
  { id: 6, label: 'RAG 知识库匹配', desc: 'JSONL 知识库语义相似度检索，匹配已知漏洞模式与攻击向量', duration: '0.6s',  status: 'done',    modelIcon: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253' },
  { id: 7, label: '多维风险评分', desc: 'R_func = 0.25×Aₐ + 0.15×Gₐ + 0.20×Sₐ + 0.15×Bₐ + 0.15×Kₐ + 0.10×Cₐ − 0.20×Pₐ', duration: '1.5s',  status: 'done',    modelIcon: 'M3 4h13M3 8h9m-9 4h9m5-4v12m0 0l-4-4m4 4l4-4' },
  { id: 8, label: 'LLM 推理定位', desc: 'DeepSeek v4-pro 大模型推理，筛选高价值函数生成漏洞发现与攻击路径', duration: '8.6s',  status: 'done',    modelIcon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
  { id: 9, label: '漏洞验证',      desc: 'Slither 静态工具验证 + LLM 验证智能体综合判断，双重交叉验证机制', duration: '3.2s',  status: 'done',    modelIcon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
  { id: 10, label: '报告生成',     desc: '汇总所有模型输出，生成 JSON + Markdown 格式审计报告与修复建议', duration: '1.1s',  status: 'done',    modelIcon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
]
</script>

<template>
  <div class="p-6 h-full">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
      <div>
        <h3 class="text-base font-semibold text-white">审计执行流程</h3>
        <p class="text-xs text-gray-500 mt-1">多模型协同推理全流程追踪</p>
      </div>
      <div class="flex items-center gap-4 text-xs text-gray-500">
        <span class="flex items-center gap-1.5">
          <span class="w-2 h-2 rounded-full bg-green-500" /> 已完成: {{ steps.filter(s => s.status === 'done').length }}
        </span>
        <span>总耗时: ~30s</span>
      </div>
    </div>

    <!-- Timeline Grid - 2 columns on wide screens -->
    <div class="grid grid-cols-1 xl:grid-cols-2 gap-3">
      <div
        v-for="step in steps"
        :key="step.id"
        class="flex items-start gap-4 p-4 bg-[#161b22] border border-[#21262d] rounded-xl hover:border-[#30363d] transition-colors group"
      >
        <!-- Step number + icon -->
        <div
          class="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 text-sm font-bold transition-colors"
          :class="{
            'bg-green-500/15 text-green-400 border border-green-500/30': step.status === 'done',
            'bg-blue-500/15 text-blue-400 border border-blue-500/30 animate-pulse': step.status === 'running',
            'bg-[#0d1117] text-gray-600 border border-[#21262d]': step.status === 'pending',
          }"
        >
          <svg v-if="step.status === 'done'" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" :d="step.modelIcon" />
          </svg>
          <span v-else>{{ step.id }}</span>
        </div>

        <!-- Content -->
        <div class="flex-1 min-w-0">
          <div class="flex items-center justify-between mb-1">
            <span class="text-sm font-medium text-gray-200 group-hover:text-white transition-colors">
              {{ step.id }}. {{ step.label }}
            </span>
            <span class="text-xs text-gray-600 font-mono ml-3 shrink-0">{{ step.duration }}</span>
          </div>
          <p class="text-xs text-gray-500 leading-relaxed">{{ step.desc }}</p>
        </div>

        <!-- Status dot -->
        <div class="pt-1.5 shrink-0">
          <div
            class="w-2 h-2 rounded-full"
            :class="{
              'bg-green-500': step.status === 'done',
              'bg-blue-500': step.status === 'running',
              'bg-gray-700': step.status === 'pending',
            }"
          />
        </div>
      </div>
    </div>
  </div>
</template>
