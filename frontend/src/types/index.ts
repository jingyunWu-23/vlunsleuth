// ============= Auth =============
export interface User {
  id: string
  username: string
  display_name: string | null
  created_at?: string
  updated_at?: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface RegisterRequest {
  username: string
  password: string
  display_name?: string
}

export interface AuthResponse {
  user: User
  access_token: string
  token_type: 'bearer'
}

// ============= Audit enums =============
export type TaskStatus =
  | 'created'
  | 'queued'
  | 'running'
  | 'cancelling'
  | 'succeeded'
  | 'failed'
  | 'cancelled'
  | 'interrupted'

export type AuditMode =
  | 'full_audit'
  | 'known_full_scan'
  | 'unknown_risk_scan'
  | 'cross_contract_scan'

export type VulnerabilityId =
  | 'VULN_REENTRANCY'
  | 'VULN_TIMESTAMP'
  | 'VULN_DELEGATECALL'
  | 'VULN_UNCHECKED_LOW_LEVEL_CALLS'
  | 'VULN_CROSS_CONTRACT_RISK'
  | 'VULN_UNKNOWN_ANOMALY'

export type Severity = 'high' | 'medium' | 'low'

export type FindingStatus = 'suspected' | 'confirmed' | 'rejected' | 'inconclusive'

export const VULN_LABELS: Record<VulnerabilityId, string> = {
  VULN_REENTRANCY: '重入漏洞',
  VULN_TIMESTAMP: '时间戳依赖',
  VULN_DELEGATECALL: '不安全委托调用',
  VULN_UNCHECKED_LOW_LEVEL_CALLS: '未检查低级调用',
  VULN_CROSS_CONTRACT_RISK: '跨合约调用风险',
  VULN_UNKNOWN_ANOMALY: '未知行为异常',
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  high: 'bg-red-600 text-white',
  medium: 'bg-orange-500 text-white',
  low: 'bg-yellow-500 text-black',
}

// ============= Audit Task =============
export interface AuditTask {
  task_id: string
  status: TaskStatus
  progress: number
  mode?: AuditMode
  can_cancel: boolean
  can_retry: boolean
  can_delete: boolean
  status_url: string
  artifacts_url: string
  events_url: string
  cancel_url: string
  retry_url: string
  report_url?: string
  contract_name?: string
  created_at?: string
  started_at?: string
  finished_at?: string
  summary?: AuditSummary
}

export interface AuditSummary {
  total_findings: number
  confirmed: number
  suspected: number
  warnings: number
  anomaly_count: number
}

export interface AuditTaskListResponse {
  tasks: AuditTask[]
  total: number
  limit: number
  offset: number
  status_counts: Record<string, number>
}

export interface TaskEvent {
  id: number
  task_id: string
  event_time: string
  event_type: string
  message: string
  payload?: Record<string, unknown>
}

// ============= Audit Request =============
export interface AuditRequest {
  source_path?: string
  mode: AuditMode
  target_vulnerabilities?: VulnerabilityId[]
  need_verification?: boolean
  need_repair?: boolean
  background_risk_screening?: boolean
  background_screening_action?: 'mark_warning' | 'audit'
  async_run?: boolean
}

// ============= Audit Report =============
export interface RiskVector {
  function_id: string
  contract_name: string
  function_signature: string
  anomaly_score: number
  gcn_score: number
  static_score: number
  business_score: number
  knowledge_score: number
  consistency_score: number
  protection_score: number
  r_func: number
  selected_scores: Record<string, number>
  warning_scores: Record<string, number>
}

export interface ModelEvidence {
  evidence_id: string
  model_id: string
  scope: 'function' | 'contract'
  contract_name: string
  function_signature: string
  function_id: string
  vulnerability_id: VulnerabilityId
  raw_score: number
  calibrated_confidence: number
  label?: string
  location_candidates?: CodeLocation[]
  feature_evidence?: Record<string, unknown>[]
  metadata?: Record<string, unknown>
}

export interface CodeLocation {
  start_line: number
  end_line: number
  start_col?: number
  end_col?: number
  snippet?: string
}

export interface VerificationResult {
  slither?: {
    matched: boolean
    detector?: string
    description?: string
  }
  llm_verification?: {
    verdict: string
    reasoning: string
    confidence: number
  }
}

export interface Finding {
  finding_id: string
  scope: 'function' | 'contract'
  status: FindingStatus
  contract_name: string
  function_signature: string
  vulnerability_id: VulnerabilityId
  severity: Severity
  confidence: number
  summary: string
  evidence: ModelEvidence[]
  knowledge?: Record<string, unknown>[]
  location?: CodeLocation[]
  verification_plan?: VerificationResult
  repair_suggestion?: RepairSuggestion
  attack_path?: string
  key_features?: string[]
}

export interface Warning {
  warning_id: string
  scope: 'function' | 'contract'
  status: 'screening_warning' | 'rejected_false_positive' | 'anomaly_warning'
  contract_name: string
  function_signature: string
  target_vulnerability: VulnerabilityId
  score: number
  summary: string
  recommended_action?: {
    action: string
    detail?: string
  }
}

export interface RepairSuggestion {
  strategy?: string
  patch_pattern?: string
  original_snippet?: string
  post_fix_checks?: string[]
}

export interface WorkflowMeta {
  mode: AuditMode
  registered_adapters: string[]
  reasoning_gate?: Record<string, unknown>
  adapter_results?: Record<string, unknown>
  verification?: Record<string, unknown>
}

export interface AuditReport {
  task_id: string
  mode: AuditMode
  workflow?: WorkflowMeta
  risk_vectors: RiskVector[]
  findings: Finding[]
  warnings: Warning[]
  metadata?: Record<string, unknown>
}

// ============= Source File (for Monaco editor) =============
export interface SourceFileInfo {
  path: string
  content: string
  contract_name?: string
}

export interface FunctionUnit {
  name: string
  signature: string
  start_line: number
  end_line: number
  contract_name: string
  risk_level: Severity | 'none'
  vulnerabilities: VulnerabilityId[]
}

export interface ContractUnit {
  name: string
  file_path: string
  functions: FunctionUnit[]
}

// ============= Health =============
export interface HealthResponse {
  status: string
  workers: number
  tasks: Record<string, number>
  database: string
}

// ============= Call Graph =============
export interface CallGraphNode {
  id: string
  name: string
  category: 'contract' | 'function'
  contractName: string
  riskLevel: Severity | 'none'
  symbolSize: number
  crossContractFindings: number
  rFunc?: number
}

export interface CallGraphEdge {
  source: string
  target: string
  callType: 'internal' | 'external'
  methodName?: string
  riskFlag: boolean
}

export interface CallGraphData {
  nodes: CallGraphNode[]
  edges: CallGraphEdge[]
}

// ============= Monaco Marker =============
export interface VulnerabilityMarker {
  startLineNumber: number
  endLineNumber: number
  startColumn: number
  endColumn: number
  severity: Severity
  message: string
  vulnerabilityId: VulnerabilityId
  confidence: number
  modelSources: string[]
  findingId: string
}
