<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, shallowRef } from 'vue'
import * as monaco from 'monaco-editor'

const props = defineProps<{
  code: string
  language?: string
}>()

const containerRef = ref<HTMLDivElement>()
const editor = shallowRef<monaco.editor.IStandaloneCodeEditor | null>(null)
let resizeObserver: ResizeObserver | null = null

onMounted(() => {
  if (!containerRef.value || !props.code) return

  editor.value = monaco.editor.create(containerRef.value, {
    value: props.code,
    language: props.language ?? 'sol',
    theme: 'vs-dark',
    fontSize: 13,
    lineHeight: 22,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    readOnly: true,
    automaticLayout: false,
    padding: { top: 12, bottom: 12 },
    glyphMargin: false,
    folding: true,
    lineNumbers: 'on',
    renderLineHighlight: 'none',
  })

  resizeObserver = new ResizeObserver(() => {
    editor.value?.layout()
  })
  resizeObserver.observe(containerRef.value)
})

onUnmounted(() => {
  resizeObserver?.disconnect()
  editor.value?.dispose()
  editor.value = null
})

watch(
  () => [props.code, props.language],
  () => {
    if (editor.value) {
      const model = editor.value.getModel()
      if (model) {
        model.setValue(props.code)
        monaco.editor.setModelLanguage(model, props.language ?? 'sol')
      }
    }
  },
)
</script>

<template>
  <div ref="containerRef" class="w-full h-full min-h-[250px]" />
</template>
