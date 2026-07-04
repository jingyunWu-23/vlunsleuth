import { computed } from 'vue'
import type { AuditReport, CallGraphData, CallGraphNode, CallGraphEdge, Severity } from '@/types'

/**
 * Builds a cross-contract call graph from audit report data.
 * Nodes = contracts + functions. Edges = inferred from findings + risk vectors.
 */
export function useCallGraph(report: () => AuditReport | null) {
  const graphData = computed<CallGraphData>(() => {
    const rp = report()
    if (!rp) return { nodes: [], edges: [] }

    return buildMockCallGraph(rp)
  })

  const summary = computed(() => {
    const d = graphData.value
    const totalCallEdges = d.edges.length
    const riskEdges = d.edges.filter((e) => e.riskFlag).length
    const highRiskNodes = d.nodes.filter((n) => n.riskLevel === 'high').length
    const crossContractFindings = d.nodes.reduce((sum, n) => sum + n.crossContractFindings, 0)
    return { totalCallEdges, riskEdges, highRiskNodes, crossContractFindings }
  })

  return { graphData, summary }
}

/**
 * Mock call graph builder.
 * In production this parses findings' evidence metadata for internal_calls/external_calls.
 * The mock produces a realistic multi-contract interaction topology.
 */
function buildMockCallGraph(report: AuditReport): CallGraphData {
  // Collect contract names from findings + risk_vectors
  const contractSet = new Set<string>()
  const funcNodesMap = new Map<string, { name: string; c: string; rf: number; risk: Severity | 'none'; ccf: number }>()

  for (const f of report.findings) {
    contractSet.add(f.contract_name)
    const key = `${f.contract_name}::${f.function_signature}`
    const existing = funcNodesMap.get(key)
    const isCC = f.vulnerability_id === 'VULN_CROSS_CONTRACT_RISK'
    const sev = f.status === 'confirmed' ? f.severity : f.status === 'suspected' ? 'medium' : 'low'
    if (!existing || (isCC && sev === 'high')) {
      funcNodesMap.set(key, {
        name: f.function_signature,
        c: f.contract_name,
        rf: f.confidence,
        risk: isCC ? f.severity : 'none',
        ccf: (existing?.ccf ?? 0) + (isCC ? 1 : 0),
      })
    }
  }

  for (const rv of report.risk_vectors) {
    contractSet.add(rv.contract_name)
    const key = `${rv.contract_name}::${rv.function_signature}`
    if (!funcNodesMap.has(key)) {
      funcNodesMap.set(key, {
        name: rv.function_signature,
        c: rv.contract_name,
        rf: rv.r_func,
        risk: 'none',
        ccf: 0,
      })
    }
  }

  // Build graph nodes
  const nodes: CallGraphNode[] = []
  const contractNodeIds = new Set<string>()

  for (const cName of contractSet) {
    const cid = `contract:${cName}`
    contractNodeIds.add(cid)
    const funcsOfContract = [...funcNodesMap.entries()].filter(([, v]) => v.c === cName)
    const maxRisk = funcsOfContract.reduce<Severity | 'none'>((worst, [, v]) => {
      if (v.risk === 'high') return 'high'
      if (v.risk === 'medium' && worst !== 'high') return 'medium'
      if (v.risk === 'low' && worst === 'none') return 'low'
      return worst
    }, 'none')
    nodes.push({
      id: cid,
      name: cName,
      category: 'contract',
      contractName: cName,
      riskLevel: maxRisk,
      symbolSize: 48 + funcsOfContract.length * 4,
      crossContractFindings: funcsOfContract.reduce((s, [, v]) => s + v.ccf, 0),
    })
  }

  for (const [key, val] of funcNodesMap) {
    const id = `func:${key}`
    nodes.push({
      id,
      name: val.name,
      category: 'function',
      contractName: val.c,
      riskLevel: val.risk,
      symbolSize: val.risk === 'high' ? 28 : val.risk === 'medium' ? 22 : 16,
      crossContractFindings: val.ccf,
      rFunc: val.rf,
    })
  }

  // Build graph edges
  const edges: CallGraphEdge[] = []
  const contractNames = [...contractSet]

  // Edges from findings flagged as cross-contract risk
  const ccFindings = report.findings.filter((f) => f.vulnerability_id === 'VULN_CROSS_CONTRACT_RISK')
  for (const f of ccFindings) {
    const srcId = `func:${f.contract_name}::${f.function_signature}`
    // Try to infer target from summary/evidence
    for (const cName of contractNames) {
      if (cName !== f.contract_name && f.summary.includes(cName)) {
        const tgtId = `contract:${cName}`
        edges.push({
          source: srcId,
          target: tgtId,
          callType: 'external',
          methodName: f.function_signature,
          riskFlag: true,
        })
        break
      }
    }
    // If no target found, link to a random other contract
    if (!edges.some((e) => e.source === srcId)) {
      const others = contractNames.filter((c) => c !== f.contract_name)
      if (others.length) {
        const tgt = others[Math.floor(Math.random() * others.length)]
        edges.push({
          source: srcId,
          target: `contract:${tgt}`,
          callType: 'external',
          methodName: f.function_signature,
          riskFlag: true,
        })
      }
    }
  }

  // Internal edges: function → its contract node
  for (const [key] of funcNodesMap) {
    const cName = key.split('::')[0]
    edges.push({
      source: `func:${key}`,
      target: `contract:${cName}`,
      callType: 'internal',
      methodName: key.split('::')[1],
      riskFlag: false,
    })
  }

  return { nodes, edges }
}
