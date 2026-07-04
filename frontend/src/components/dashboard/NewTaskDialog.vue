<script setup lang="ts">
import { ref } from 'vue'
import { useAuditStore } from '@/stores/audit'
import type { AuditMode, VulnerabilityId } from '@/types'

const emit = defineEmits<{
  close: []
  created: [taskId: string]
}>()

const auditStore = useAuditStore()
const file = ref<File | null>(null)
const mode = ref<AuditMode>('full_audit')
const needVerification = ref(true)
const loading = ref(false)
const error = ref('')

const modeLabels: Record<AuditMode, string> = {
  full_audit: '全面审计 (推荐)',
  known_full_scan: '已知漏洞扫描',
  unknown_risk_scan: '未知风险扫描',
  cross_contract_scan: '跨合约专项扫描',
}

const modeDescriptions: Record<AuditMode, string> = {
  full_audit: 'LSTM + GCN + DeepSVDD + 推理 + 验证 + 修复建议',
  known_full_scan: '仅 LSTM 已知漏洞检测',
  unknown_risk_scan: 'DeepSVDD + LSTM 异常检测',
  cross_contract_scan: '仅 GCN 跨合约风险分析',
}

function handleFileChange(e: Event) {
  const input = e.target as HTMLInputElement
  if (input.files?.length) {
    file.value = input.files[0]
  }
}

async function handleSubmit() {
  error.value = ''
  if (!file.value) {
    error.value = '请选择一个合约文件'
    return
  }

  loading.value = true
  const formData = new FormData()
  formData.append('file', file.value)
  formData.append('mode', mode.value)
  formData.append('need_verification', String(needVerification.value))
  formData.append('async_run', 'true')

  const task = await auditStore.createTask(formData)
  loading.value = false

  if (task) {
    emit('created', task.task_id)
  } else {
    error.value = auditStore.error || '创建任务失败'
  }
}
</script>

<template>
  <div class="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" @click.self="emit('close')">
    <div class="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
      <div class="flex items-center justify-between p-5 border-b border-[#30363d]">
        <h2 class="text-lg font-semibold text-white">新建检测任务</h2>
        <button @click="emit('close')" class="text-gray-500 hover:text-white transition-colors">
          <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div class="p-5 space-y-5">
        <!-- File Upload -->
        <div>
          <label class="block text-sm text-gray-400 mb-2">合约文件</label>
          <label
            class="flex flex-col items-center gap-2 p-6 border-2 border-dashed border-[#30363d] rounded-xl cursor-pointer hover:border-blue-500/50 transition-colors"
          >
            <svg v-if="!file" class="w-10 h-10 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            <svg v-else class="w-10 h-10 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span v-if="!file" class="text-sm text-gray-500">拖拽 .sol / .zip 文件到此处，或点击选择</span>
            <span v-else class="text-sm text-blue-400 font-medium">{{ file.name }}</span>
            <input type="file" accept=".sol,.zip" class="hidden" @change="handleFileChange" />
          </label>
        </div>

        <!-- Mode -->
        <div>
          <label class="block text-sm text-gray-400 mb-2">审计模式</label>
          <div class="space-y-2">
            <label
              v-for="(desc, m) in modeLabels"
              :key="m"
              class="flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors"
              :class="mode === m ? 'border-blue-500 bg-blue-600/10' : 'border-[#30363d] hover:border-[#484f58]'"
            >
              <input v-model="mode" type="radio" :value="m" class="mt-0.5 accent-blue-500" />
              <div>
                <div class="text-white text-sm font-medium">{{ desc }}</div>
                <div class="text-gray-500 text-xs mt-0.5">{{ modeDescriptions[m as AuditMode] }}</div>
              </div>
            </label>
          </div>
        </div>

        <!-- Verification Toggle -->
        <div class="flex items-center justify-between p-3 bg-[#0d1117] rounded-lg border border-[#30363d]">
          <div>
            <div class="text-white text-sm">Slither 验证</div>
            <div class="text-gray-500 text-xs">使用 Slither 静态分析验证漏洞</div>
          </div>
          <button
            @click="needVerification = !needVerification"
            class="relative w-10 h-5 rounded-full transition-colors"
            :class="needVerification ? 'bg-blue-600' : 'bg-gray-700'"
          >
            <span
              class="absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform"
              :class="needVerification ? 'left-5' : 'left-0.5'"
            />
          </button>
        </div>

        <div v-if="error" class="text-sm text-red-400 bg-red-400/10 px-3 py-2 rounded-lg">
          {{ error }}
        </div>

        <div class="flex items-center gap-3 pt-2">
          <button
            @click="emit('close')"
            class="flex-1 py-2.5 bg-[#0d1117] border border-[#30363d] text-gray-300 text-sm rounded-lg hover:bg-[#1c2128] transition-colors"
          >
            取消
          </button>
          <button
            @click="handleSubmit"
            :disabled="loading || !file"
            class="flex-1 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:text-gray-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {{ loading ? '创建中...' : '开始检测' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
