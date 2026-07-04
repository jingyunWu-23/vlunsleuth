<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useAuditStore } from '@/stores/audit'
import { reportsApi } from '@/api'

const route = useRoute()
const auditStore = useAuditStore()

const markdownContent = ref('')
const loadingMarkdown = ref(false)

const taskId = route.params.taskId as string

onMounted(async () => {
  await auditStore.fetchReport(taskId)
  loadingMarkdown.value = true
  try {
    const res = await reportsApi.getReportMarkdown(taskId)
    markdownContent.value = typeof res.data === 'string' ? res.data : JSON.stringify(res.data)
  } catch {
    markdownContent.value = '无法加载报告内容'
  } finally {
    loadingMarkdown.value = false
  }
})
</script>

<template>
  <div class="p-6 max-w-4xl mx-auto">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-xl font-bold text-white">审计报告</h1>
      <div class="flex items-center gap-3">
        <a
          v-if="taskId"
          :href="`/api/v1/audits/${taskId}/report.json`"
          class="px-3 py-2 bg-[#161b22] border border-[#30363d] text-gray-300 text-sm rounded-lg hover:bg-[#1c2128] transition-colors"
        >
          下载 JSON
        </a>
        <a
          v-if="taskId"
          :href="`/api/v1/audits/${taskId}/report.md`"
          class="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
        >
          下载 Markdown
        </a>
      </div>
    </div>

    <!-- Markdown Report -->
    <div class="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
      <div v-if="loadingMarkdown" class="text-center py-12 text-gray-400">
        <svg class="animate-spin w-6 h-6 mx-auto mb-3" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        加载中...
      </div>
      <pre v-else class="text-sm text-gray-300 whitespace-pre-wrap font-mono leading-relaxed">{{ markdownContent }}</pre>
    </div>
  </div>
</template>
