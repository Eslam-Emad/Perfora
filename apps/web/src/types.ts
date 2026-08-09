export type ProviderId = "opencode" | "ollama" | "openai";
export type AuditType = "performance" | "security";

export interface ToolStatus {
  id: string;
  label: string;
  available: boolean;
  version?: string;
  detail: string;
}

export interface ModelInfo {
  provider: ProviderId;
  id: string;
  label: string;
  available: boolean;
  compatible: boolean;
  capability_status: "compatible" | "unsupported" | "unknown";
  locality: "local" | "remote" | "unknown";
  context_window?: number;
  metadata: Record<string, unknown>;
}

export interface ProviderCatalog {
  provider: ProviderId;
  available: boolean;
  detail: string;
  models: ModelInfo[];
}

export interface SetupStatus {
  tools: ToolStatus[];
  providers: ProviderCatalog[];
}

export interface RepositorySnapshot {
  path: string;
  name: string;
  valid: boolean;
  detail: string;
  is_flutter: boolean;
  is_git: boolean;
  branch?: string;
  commit_sha?: string;
  clean?: boolean;
  fingerprint?: string;
  packages: string[];
}

export interface Finding {
  id: string;
  audit_id: string;
  rule_id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  status: "confirmed" | "hypothesis";
  file: string;
  line: number;
  symbol?: string;
  framework: string;
  evidence: string[];
  explanation: string;
  recommendation: string;
  model_explanation?: string;
  fix_status: string;
}

export interface AuditEvent {
  sequence: number;
  type: string;
  message: string;
  progress: number;
  created_at: string;
}

export interface AuditRecord {
  id: string;
  repository: RepositorySnapshot;
  provider: ProviderId;
  model_id: string;
  audit_type: AuditType;
  model_metadata: Record<string, unknown>;
  status: "queued" | "running" | "partial" | "completed" | "failed" | "cancelled";
  created_at: string;
  updated_at: string;
  findings: Finding[];
  events: AuditEvent[];
  error?: string;
  context_manifest: string[];
}

export interface FixProposal {
  finding_id: string;
  audit_id: string;
  summary: string;
  risk: string;
  patch: string;
  expected_head: string;
}
