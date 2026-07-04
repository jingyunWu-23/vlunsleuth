<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const username = ref('')
const displayName = ref('')
const password = ref('')
const confirmPassword = ref('')
const error = ref('')
const loading = ref(false)

async function handleSubmit() {
  error.value = ''
  if (!username.value || !password.value) {
    error.value = '请填写用户名和密码'
    return
  }
  if (username.value.length < 3) {
    error.value = '用户名至少需要3个字符'
    return
  }
  if (password.value.length < 8) {
    error.value = '密码至少需要8个字符'
    return
  }
  if (password.value !== confirmPassword.value) {
    error.value = '两次输入的密码不一致'
    return
  }

  loading.value = true
  const ok = await authStore.register({
    username: username.value,
    password: password.value,
    display_name: displayName.value || undefined,
  })
  loading.value = false
  if (ok) {
    router.push('/')
  } else {
    error.value = '注册失败，请重试'
  }
}
</script>

<template>
  <div class="min-h-screen bg-[#0d1117] flex items-center justify-center px-4">
    <div class="w-full max-w-md">
      <div class="text-center mb-8">
        <div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center mx-auto mb-4">
          <svg class="w-10 h-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
              d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        </div>
        <h1 class="text-2xl font-bold text-white">创建账号</h1>
        <p class="text-gray-400 mt-2 text-sm">注册 SmartAudit AI 平台</p>
      </div>

      <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
        <form @submit.prevent="handleSubmit" class="space-y-4">
          <div>
            <label class="block text-sm text-gray-400 mb-1.5">用户名</label>
            <input
              v-model="username"
              type="text"
              class="w-full px-3 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-white text-sm placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
              placeholder="至少3个字符"
            />
          </div>

          <div>
            <label class="block text-sm text-gray-400 mb-1.5">显示名称 (可选)</label>
            <input
              v-model="displayName"
              type="text"
              class="w-full px-3 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-white text-sm placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
              placeholder="显示名称"
            />
          </div>

          <div>
            <label class="block text-sm text-gray-400 mb-1.5">密码</label>
            <input
              v-model="password"
              type="password"
              class="w-full px-3 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-white text-sm placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
              placeholder="至少8个字符"
            />
          </div>

          <div>
            <label class="block text-sm text-gray-400 mb-1.5">确认密码</label>
            <input
              v-model="confirmPassword"
              type="password"
              class="w-full px-3 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-white text-sm placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-colors"
              placeholder="再次输入密码"
            />
          </div>

          <div v-if="error" class="text-sm text-red-400 bg-red-400/10 px-3 py-2 rounded-lg">
            {{ error }}
          </div>

          <button
            type="submit"
            :disabled="loading"
            class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {{ loading ? '注册中...' : '注册' }}
          </button>
        </form>

        <p class="mt-4 text-center text-sm text-gray-500">
          已有账号？
          <router-link to="/login" class="text-blue-400 hover:text-blue-300 transition-colors">
            立即登录
          </router-link>
        </p>
      </div>
    </div>
  </div>
</template>
