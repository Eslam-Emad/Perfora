export type ProviderId = "opencode" | "ollama" | "openai";
export type AuditType = "performance" | "security";
export type TriageStatus =
  | "new"
  | "investigating"
  | "in_progress"
  | "resolved"
  | "verified_resolved"
  | "false_positive"
  | "risk_accepted"
  | "reopened";
export type ComparisonStatus = "new" | "unchanged" | "regressed" | "severity_changed";
export type VerificationOutcome =
  | "verified_resolved"
  | "still_present"
  | "inconclusive"
  | "error";

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

export interface ModelEnrichment {
  provider?: ProviderId;
  model_id?: string;
  explanation: string;
  recommendation?: string;
  generated_at: string;
}

export interface FindingNote {
  id: string;
  body: string;
  created_at: string;
}

export interface FindingStatusChange {
  from_status: TriageStatus;
  to_status: TriageStatus;
  reason?: string;
  changed_at: string;
}

export interface VerificationAttempt {
  id: string;
  outcome: VerificationOutcome;
  message: string;
  started_at: string;
  completed_at: string;
  repository: RepositorySnapshot;
  analyzer_version: string;
  rule_pack: RulePackMetadata;
  scan_coverage: ScanCoverage;
  rule_executed: boolean;
  source_present: boolean;
  file_scanned: boolean;
  observed_file?: string;
  observed_line?: number;
  observed_evidence: string[];
}

export interface Finding {
  id: string;
  audit_id: string;
  fingerprint: string;
  rule_id: string;
  rule_version: string;
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
  control_group?: string;
  platforms?: string[];
  standards?: SecurityStandardReference[];
  detection_limitations?: string[];
  manual_verification?: string[];
  false_positive_guidance?: string;
  model_enrichment?: ModelEnrichment;
  triage_status: TriageStatus;
  comparison_status?: ComparisonStatus;
  owner?: string;
  due_at?: string;
  resolution_commit?: string;
  disposition_reason?: string;
  suppression_expires_at?: string;
  ticket_url?: string;
  notes: FindingNote[];
  status_history: FindingStatusChange[];
  first_seen_at?: string;
  last_seen_at?: string;
  verification_attempts?: VerificationAttempt[];
}

export interface SecurityStandardReference {
  id: string;
  title: string;
  url: string;
}

export interface DependencyComponent {
  bom_ref: string;
  name: string;
  version: string;
  ecosystem: string;
  source_file: string;
  scope: "required" | "optional" | "excluded" | "unknown";
  direct?: boolean;
  purl?: string;
  license?: string;
  privacy_category?: string;
  privacy_sensitive: boolean;
}

export interface DependencyInventory {
  components: DependencyComponent[];
  manifests: string[];
  coverage_by_ecosystem: Record<string, number>;
  license_counts: Record<string, number>;
  privacy_sdk_counts: Record<string, number>;
  vulnerability_matching: "not_requested" | "disabled" | "completed";
}

export interface RulePackMetadata {
  id: string;
  version: string;
}

export interface ScanCoverage {
  files_discovered: number;
  files_scanned: number;
  files_skipped: number;
  scanned_by_type: Record<string, number>;
  skipped_by_reason: Record<string, number>;
  rules_executed: string[];
  scanned_files?: string[];
  skipped_files_by_reason?: Record<string, string[]>;
  coverage_by_platform?: Record<string, number>;
  rules_by_control_group?: Record<string, string[]>;
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
  record_version?: number;
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
  analyzer_version?: string;
  rule_pack?: RulePackMetadata;
  scan_coverage?: ScanCoverage;
  baseline_audit_id?: string;
  dependency_inventory?: DependencyInventory;
}

export interface AgentPrompt {
  finding_id: string;
  audit_id: string;
  prompt: string;
  redacted: boolean;
  generated_at: string;
}

export interface FindingUpdate {
  triage_status?: TriageStatus;
  owner?: string | null;
  due_at?: string | null;
  resolution_commit?: string | null;
  disposition_reason?: string | null;
  suppression_expires_at?: string | null;
  ticket_url?: string | null;
  note?: string | null;
}

export interface SeverityChange {
  fingerprint: string;
  finding_id: string;
  baseline_finding_id: string;
  from_severity: Finding["severity"];
  to_severity: Finding["severity"];
}

export interface AuditComparison {
  current_audit_id: string;
  baseline_audit_id?: string;
  new_finding_ids: string[];
  unchanged_finding_ids: string[];
  regressed_finding_ids: string[];
  severity_changes: SeverityChange[];
  resolved_findings: Finding[];
  dependency_changes?: {
    added: DependencyComponent[];
    removed: DependencyComponent[];
    updated: Array<{
      ecosystem: string;
      name: string;
      from_version: string;
      to_version: string;
    }>;
  };
}
