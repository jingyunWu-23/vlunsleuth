<script setup lang="ts">
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuditStore } from '@/stores/audit'

const router = useRouter()
const route = useRoute()
const auditStore = useAuditStore()

const isCollapsed = ref(false)

function toggleCollapse() {
  isCollapsed.value = !isCollapsed.value
}

function navigateTo(path: string) {
  router.push(path)
}

function isActive(path: string) {
  return route.path === path
}

const confirmedCount = auditStore.confirmedFindings?.length ?? 0
</script>

<template>
  <aside
    class="h-screen bg-[#0d1117] border-r border-[#21262d] flex flex-col transition-all duration-300"
    :class="isCollapsed ? 'w-16' : 'w-64'"
  >
    <!-- Logo -->
    <div class="flex items-center gap-3 px-4 h-14 border-b border-[#21262d] shrink-0">
      <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shrink-0">
        <svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      </div>
      <span v-if="!isCollapsed" class="text-white font-bold text-sm whitespace-nowrap">VulnSleuth</span>
    </div>

    <!-- New Task Button -->
    <div class="px-3 py-3" v-if="!isCollapsed">
      <button
        @click="navigateTo('/')"
        class="w-full flex items-center justify-center gap-2 px-3 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors"
      >
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
        新建检测任务
      </button>
    </div>

    <!-- Task Info -->
    <div v-if="!isCollapsed && auditStore.currentTask" class="px-4 py-3 text-xs text-gray-400 border-b border-[#21262d]">
      <div class="flex items-center justify-between mb-1">
        <span>项目名</span>
        <span class="text-gray-300">{{ auditStore.currentTask.contract_name || '未命名' }}</span>
      </div>
      <div class="flex items-center justify-between mb-1">
        <span>合约数量</span>
        <span class="text-gray-300">--</span>
      </div>
      <div class="flex items-center justify-between">
        <span>检测时间</span>
        <span class="text-gray-300">{{ auditStore.currentTask.created_at?.slice(0, 10) || '--' }}</span>
      </div>
    </div>

    <!-- Nav Menu -->
    <nav class="flex-1 overflow-y-auto py-3 px-3 space-y-1" :class="{ 'px-2': isCollapsed }">
      <button
        v-for="item in [
          { icon: 'M4 6h16M4 12h16M4 18h16', label: '总览', path: '/' },
          { icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01', label: '检测结果', badge: confirmedCount, badgeColor: 'bg-red-500', path: '/audit/detail' },
          { icon: 'M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7', label: '跨合约调用图', path: '/cross-contract' },
          { icon: 'M3 4h13M3 8h9m-9 4h6m4 0l4-4m0 0l4 4m-4-4v12', label: '函数风险排名', path: '/risk-ranking' },
          { icon: 'M13 7h8m0 0v8m0-8l-8 8-4-4-6 6', label: '修复建议', path: '/repair' },
          { icon: 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z', label: '报告', path: auditStore.currentTask?.task_id ? `/report/${auditStore.currentTask.task_id}` : '/report' },
          { icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z', label: '历史任务', path: '/tasks' },
        ]"
        :key="item.label"
        @click="navigateTo(item.path)"
        :class="[
          'w-full flex items-center gap-3 px-3 py-2.5 text-sm rounded-lg transition-colors text-left',
          isActive(item.path)
            ? 'bg-blue-600/20 text-blue-400 border border-blue-600/30'
            : 'text-gray-400 hover:text-gray-200 hover:bg-[#1c2128]',
        ]"
      >
        <svg class="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
          <path stroke-linecap="round" stroke-linejoin="round" :d="item.icon" />
        </svg>
        <span v-if="!isCollapsed" class="flex-1 text-left">{{ item.label }}</span>
        <span
          v-if="!isCollapsed && item.badge"
          class="text-xs text-white px-1.5 py-0.5 rounded-full min-w-[18px] text-center"
          :class="item.badgeColor"
        >
          {{ item.badge }}
        </span>
      </button>
    </nav>

    <!-- Collapse Toggle -->
    <div class="border-t border-[#21262d] shrink-0">
      <button
        @click="toggleCollapse"
        class="w-full flex items-center justify-center py-3 text-gray-500 hover:text-gray-300 transition-colors"
      >
        <svg
          class="w-5 h-5 transition-transform"
          :class="{ 'rotate-180': isCollapsed }"
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
        </svg>
      </button>
    </div>
  </aside>
</template>
