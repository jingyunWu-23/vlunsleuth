<script setup lang="ts">
import { computed } from 'vue'
import { useAuditStore } from '@/stores/audit'
import { VULN_LABELS } from '@/types'

const auditStore = useAuditStore()

const displayedProjects = computed(() => auditStore.contractProjects.slice(0, 8))

function riskPercent(score: number) {
  return `${Math.round((score || 0) * 100)}%`
}
</script>

<template>
  <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4 mb-4">
    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-blue-500/30 transition-colors">
      <div>
        <div class="text-gray-400 text-xs mb-1">输入合约总数</div>
        <div class="text-3xl font-bold text-blue-400">{{ auditStore.inputContractTotal }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5A3.375 3.375 0 0010.125 2.25H6.75A2.25 2.25 0 004.5 4.5v15A2.25 2.25 0 006.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-5.25z" />
        </svg>
      </div>
    </div>

    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-green-500/30 transition-colors">
      <div>
        <div class="text-gray-400 text-xs mb-1">正常合约</div>
        <div class="text-3xl font-bold text-green-400">{{ auditStore.normalContractCount }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
    </div>

    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-red-500/30 transition-colors">
      <div>
        <div class="text-gray-400 text-xs mb-1">异常合约</div>
        <div class="text-3xl font-bold text-red-400">{{ auditStore.abnormalContractCount }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3.75m0 3.75h.008v.008H12V16.5zm8.25 3.75l-7.5-13.5a.75.75 0 00-1.31 0l-7.5 13.5A.75.75 0 004.59 21h14.82a.75.75 0 00.66-1.125z" />
        </svg>
      </div>
    </div>

    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-orange-500/30 transition-colors">
      <div>
        <div class="text-gray-400 text-xs mb-1">漏洞发现</div>
        <div class="text-3xl font-bold text-orange-400">{{ auditStore.currentReport?.findings.length ?? 0 }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      </div>
    </div>

    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex items-center justify-between hover:border-purple-500/30 transition-colors">
      <div>
        <div class="text-gray-400 text-xs mb-1">预警项</div>
        <div class="text-3xl font-bold text-purple-400">{{ auditStore.currentReport?.warnings.length ?? 0 }}</div>
      </div>
      <div class="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
        <svg class="w-5 h-5 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
    </div>
  </div>

  <div v-if="auditStore.contractProjects.length" class="bg-[#161b22] border border-[#30363d] rounded-xl mb-4 overflow-hidden">
    <div class="flex items-center justify-between px-4 py-3 border-b border-[#30363d]">
      <div>
        <h3 class="text-sm font-semibold text-white">合约项目检测结果</h3>
        <p class="text-xs text-gray-500 mt-0.5">按上传包解析出的合约单位聚合风险状态</p>
      </div>
      <div class="text-xs text-gray-500">
        {{ auditStore.abnormalContractCount }} / {{ auditStore.inputContractTotal }} 异常
      </div>
    </div>

    <div class="divide-y divide-[#30363d]">
      <div
        v-for="project in displayedProjects"
        :key="project.project_id"
        class="grid grid-cols-[minmax(0,1fr)_110px_100px_120px] gap-3 items-center px-4 py-3 hover:bg-[#0d1117]/60 transition-colors"
      >
        <div class="min-w-0">
          <div class="flex items-center gap-2">
            <span
              class="w-2 h-2 rounded-full shrink-0"
              :class="project.status === 'abnormal' ? 'bg-red-400' : 'bg-green-400'"
            />
            <span class="text-sm font-medium text-white truncate">{{ project.project_name }}</span>
            <span
              class="text-[11px] px-2 py-0.5 rounded-full border"
              :class="project.status === 'abnormal' ? 'text-red-400 border-red-500/30 bg-red-500/10' : 'text-green-400 border-green-500/30 bg-green-500/10'"
            >
              {{ project.status === 'abnormal' ? '异常' : '正常' }}
            </span>
          </div>
          <div class="text-xs text-gray-500 mt-1 truncate">{{ project.source_path }}</div>
        </div>

        <div class="text-xs text-gray-400">
          函数 <span class="text-gray-200 font-medium">{{ project.function_count }}</span>
        </div>
        <div class="text-xs text-gray-400">
          风险 <span class="text-gray-200 font-medium">{{ riskPercent(project.max_risk) }}</span>
        </div>
        <div class="text-right text-xs min-w-0">
          <div class="text-gray-300">{{ project.finding_count }} 发现 / {{ project.warning_count }} 预警</div>
          <div v-if="project.vulnerabilities.length" class="text-gray-500 truncate mt-1">
            {{ project.vulnerabilities.slice(0, 2).map((v) => VULN_LABELS[v] || v).join('、') }}
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="flex items-center justify-between mb-4">
    <div class="text-sm text-gray-400">
      <span v-if="auditStore.currentReport">
        共输入 <span class="text-white font-medium">{{ auditStore.inputContractTotal }}</span> 个合约，
        检测后正常 <span class="text-green-400 font-medium">{{ auditStore.normalContractCount }}</span> 个，
        异常 <span class="text-red-400 font-medium">{{ auditStore.abnormalContractCount }}</span> 个。
      </span>
    </div>
  </div>
</template>
