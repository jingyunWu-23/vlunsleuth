<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, shallowRef } from 'vue'
import * as monaco from 'monaco-editor'

const props = defineProps<{
  original: string
  modified: string
  language?: string
  readOnly?: boolean
}>()

const containerRef = ref<HTMLDivElement>()
const diffEditor = shallowRef<monaco.editor.IStandaloneDiffEditor | null>(null)
let resizeObserver: ResizeObserver | null = null

onMounted(() => {
  if (!containerRef.value) return

  diffEditor.value = monaco.editor.createDiffEditor(containerRef.value, {
    theme: 'vs-dark',
    fontSize: 13,
    lineHeight: 22,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    readOnly: props.readOnly ?? true,
    automaticLayout: false,
    renderSideBySide: true,
    padding: { top: 12, bottom: 12 },
    originalEditable: false,
  })

  updateModel()

  resizeObserver = new ResizeObserver(() => {
    diffEditor.value?.layout()
  })
  resizeObserver.observe(containerRef.value)
})

onUnmounted(() => {
  resizeObserver?.disconnect()
  diffEditor.value?.dispose()
  diffEditor.value = null
})

function updateModel() {
  if (!diffEditor.value) return
  const lang = props.language ?? 'sol'
  const originalModel = monaco.editor.createModel(props.original, lang)
  const modifiedModel = monaco.editor.createModel(props.modified, lang)
  diffEditor.value.setModel({
    original: originalModel,
    modified: modifiedModel,
  })
}

watch(
  () => [props.original, props.modified, props.language],
  () => {
    if (diffEditor.value) {
      const de = diffEditor.value
      const lang = props.language ?? 'sol'
      const origModel = de.getModel()?.original
      const modModel = de.getModel()?.modified
      if (origModel && modModel) {
        origModel.setValue(props.original)
        modModel.setValue(props.modified)
        monaco.editor.setModelLanguage(origModel, lang)
        monaco.editor.setModelLanguage(modModel, lang)
      } else {
        updateModel()
      }
    }
  },
)

defineExpose({
  getDiffEditor: () => diffEditor.value,
})
</script>

<template>
  <div ref="containerRef" class="w-full h-full min-h-[300px]" />
</template>
