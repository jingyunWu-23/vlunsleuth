<script setup lang="ts">
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const userMenuOpen = ref(false)

const breadcrumbs = [
  { label: '项目', path: '/' },
  { label: '安全审计', path: '/' },
]

function handleLogout() {
  authStore.logout()
  router.push('/login')
}

function toggleUserMenu() {
  userMenuOpen.value = !userMenuOpen.value
}
</script>

<template>
  <header class="h-14 bg-[#0d1117] border-b border-[#21262d] flex items-center justify-between px-6 shrink-0">
    <!-- Breadcrumb -->
    <div class="flex items-center gap-2 text-sm">
      <template v-for="(crumb, i) in breadcrumbs" :key="crumb.label">
        <svg v-if="i > 0" class="w-4 h-4 text-gray-600" fill="currentColor" viewBox="0 0 24 24">
          <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6-6-6z" />
        </svg>
        <router-link
          :to="crumb.path"
          class="text-gray-400 hover:text-gray-200 transition-colors"
        >
          {{ crumb.label }}
        </router-link>
      </template>
      <span v-if="route.params.taskId" class="text-gray-400 text-xs font-mono">
        #{{ String(route.params.taskId).slice(0, 12) }}...
      </span>
    </div>

    <!-- Right section -->
    <div class="flex items-center gap-4">
      <!-- Model Status -->
      <div class="flex items-center gap-2 text-xs text-gray-400">
        <span class="relative flex h-2.5 w-2.5">
          <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
          <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
        </span>
        <span>模型状态: 正常</span>
      </div>

      <!-- User Menu -->
      <div class="relative">
        <button
          @click="toggleUserMenu"
          class="flex items-center gap-2 text-sm text-gray-300 hover:text-white transition-colors"
        >
          <div class="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-xs font-medium">
            {{ authStore.displayName?.charAt(0)?.toUpperCase() }}
          </div>
          <span class="hidden sm:block">{{ authStore.displayName }}</span>
          <svg class="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
          </svg>
        </button>

        <!-- Dropdown -->
        <div
          v-if="userMenuOpen"
          class="absolute right-0 mt-2 w-48 bg-[#1c2128] border border-[#30363d] rounded-lg shadow-xl py-1 z-50"
        >
          <div class="px-4 py-2 text-xs text-gray-400 border-b border-[#30363d]">
            {{ authStore.user?.username }}
          </div>
          <button
            @click="handleLogout"
            class="w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-[#2d333b] transition-colors"
          >
            退出登录
          </button>
        </div>
      </div>
    </div>
  </header>
</template>
