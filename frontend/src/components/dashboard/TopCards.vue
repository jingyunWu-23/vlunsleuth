<script setup lang="ts">
import { useAuditStore } from '@/stores/audit'

const auditStore = useAuditStore()
</script>

<template>
  <div class="grid grid-cols-4 gap-4 mb-4">
    <!-- Verified Findings -->
    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-red-500/30 transition-colors cursor-pointer">
      <div>
        <div class="text-gray-400 text-xs mb-1">已验证漏洞</div>
        <div class="text-3xl font-bold text-red-400">{{ auditStore.confirmedFindings.length }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      </div>
    </div>

    <!-- Suspected Findings -->
    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-orange-500/30 transition-colors cursor-pointer">
      <div>
        <div class="text-gray-400 text-xs mb-1">疑似漏洞</div>
        <div class="text-3xl font-bold text-orange-400">{{ auditStore.suspectedFindings.length }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
    </div>

    <!-- Other Warnings -->
    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-purple-500/30 transition-colors cursor-pointer">
      <div>
        <div class="text-gray-400 text-xs mb-1">其他潜在风险</div>
        <div class="text-3xl font-bold text-purple-400">{{ auditStore.otherWarnings.length }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
    </div>

    <!-- Anomaly Warnings -->
    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-cyan-500/30 transition-colors cursor-pointer">
      <div>
        <div class="text-gray-400 text-xs mb-1">未知异常风险</div>
        <div class="text-3xl font-bold text-cyan-400">{{ auditStore.anomalyWarnings.length }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      </div>
    </div>
  </div>

  <!-- Action Bar -->
  <div class="flex items-center justify-between mb-4">
    <div class="text-sm text-gray-400">
      <span v-if="auditStore.currentReport">
        共检测到 <span class="text-white font-medium">{{ auditStore.currentReport.findings.length }}</span> 个漏洞发现，
        <span class="text-white font-medium">{{ auditStore.currentReport.warnings.length }}</span> 个预警项
      </span>
    </div>
  </div>
</template>
