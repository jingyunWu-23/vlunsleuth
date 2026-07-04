<script setup lang="ts">
import { ref, onMounted, watch, shallowRef } from 'vue'
import * as monaco from 'monaco-editor'
import type { Finding, VulnerabilityMarker } from '@/types'

const props = defineProps<{
  findings: Finding[]
  selectedFinding: Finding | null
}>()

const emit = defineEmits<{
  selectFinding: [finding: Finding]
}>()

const editorContainer = ref<HTMLDivElement>()
const editor = shallowRef<monaco.editor.IStandaloneCodeEditor | null>(null)

// Mock Solidity source - in production this comes from the audit report or API
const mockSolidityCode = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // 存款函数
    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
    }

    // 提款函数 - 存在重入漏洞
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // 漏洞: 状态更新在外部调用之后
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}`

function buildMarkers(): VulnerabilityMarker[] {
  return props.findings.map((f) => {
    const loc = f.location?.[0] ?? f.evidence[0]?.location_candidates?.[0]
    return {
      startLineNumber: loc?.start_line ?? 20,
      endLineNumber: loc?.end_line ?? 22,
      startColumn: loc?.start_col ?? 1,
      endColumn: loc?.end_col ?? 80,
      severity: f.severity,
      message: f.summary,
      vulnerabilityId: f.vulnerability_id,
      confidence: f.confidence,
      modelSources: f.evidence.map((e) => e.model_id),
      findingId: f.finding_id,
    }
  })
}

onMounted(() => {
  if (!editorContainer.value) return

  const ed = monaco.editor.create(editorContainer.value, {
    value: mockSolidityCode,
    language: 'sol',
    theme: 'vs-dark',
    fontSize: 13,
    lineHeight: 22,
    minimap: { enabled: true, scale: 1, showSlider: 'mouseover' },
    lineNumbers: 'on',
    renderLineHighlight: 'line',
    scrollBeyondLastLine: false,
    readOnly: false,
    automaticLayout: true,
    padding: { top: 12, bottom: 12 },
  })

  editor.value = ed

  // Apply decorations from findings
  applyDecorations(ed)

  ed.onMouseDown((e) => {
    if (!e.target.position) return
    const line = e.target.position.lineNumber
    const markers = buildMarkers()
    const match = markers.find(
      (m) => line >= m.startLineNumber && line <= m.endLineNumber,
    )
    if (match) {
      const finding = props.findings.find((f) => f.finding_id === match.findingId)
      if (finding) emit('selectFinding', finding)
    }
  })
})

function applyDecorations(ed: monaco.editor.IStandaloneCodeEditor) {
  const markers = buildMarkers()
  const decorations: monaco.editor.IModelDeltaDecoration[] = markers.map((m) => ({
    range: new monaco.Range(m.startLineNumber, m.startColumn, m.endLineNumber, m.endColumn),
    options: {
      isWholeLine: true,
      className: `vuln-line vuln-${m.severity}`,
      glyphMarginClassName: `vuln-glyph vuln-glyph-${m.severity}`,
      glyphMarginHoverMessage: { value: `**${m.vulnerabilityId.replace('VULN_', '')}** (${m.confidence.toFixed(2)})\n\n${m.message}\n\n来源: ${m.modelSources.join(', ')}` },
      hoverMessage: {
        value: [
          `### ${m.vulnerabilityId.replace('VULN_', '').replace(/_/g, ' ')}`,
          '',
          `**严重等级**: ${m.severity.toUpperCase()}`,
          `**置信度**: ${(m.confidence * 100).toFixed(0)}%`,
          `**模型来源**: ${m.modelSources.join(', ')}`,
          '',
          m.message,
        ].join('\n'),
      },
      inlineClassName: `vuln-inline vuln-inline-${m.severity}`,
      overviewRuler: {
        color: m.severity === 'high' ? '#f85149' : m.severity === 'medium' ? '#d2991d' : '#e3b341',
        position: monaco.editor.OverviewRulerLane.Right,
      },
    },
  }))

  ed.deltaDecorations([], decorations)
}

watch(() => props.selectedFinding, (finding) => {
  if (!finding || !editor.value) return
  const loc = finding.location?.[0] ?? finding.evidence[0]?.location_candidates?.[0]
  if (loc) {
    editor.value.revealLineInCenter(loc.start_line)
    editor.value.setPosition({ lineNumber: loc.start_line, column: 1 })
  }
})
</script>

<template>
  <div ref="editorContainer" class="w-full h-full" />
</template>

<style scoped>
.vuln-line.vuln-high {
  background: rgba(248, 81, 73, 0.12) !important;
}
.vuln-line.vuln-medium {
  background: rgba(210, 153, 29, 0.12) !important;
}
.vuln-line.vuln-low {
  background: rgba(227, 179, 65, 0.1) !important;
}
</style>
