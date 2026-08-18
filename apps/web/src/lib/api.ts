import type {
  AuditRecord,
  AuditComparison,
  AuditType,
  AgentPrompt,
  Finding,
  FindingUpdate,
  PortfolioSummary,
  ProviderCatalog,
  ProviderId,
  ProviderSettingsSnapshot,
  ProviderSettingsUpdateResult,
  RepositorySnapshot,
  RuntimeArtifactKind,
  RuntimeBuildMode,
  RuntimeCapture,
  RuntimeCaptureComparison,
  SetupStatus,
  TicketHandoff,
  VerificationAttempt,
} from "../types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(body?.detail || `Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  setup: () => request<SetupStatus>("/api/setup"),
  models: () =>
    request<{ providers: ProviderCatalog[] }>("/api/providers/models").then(
      (catalogResponse) => catalogResponse.providers,
    ),
  providerSettings: () =>
    request<ProviderSettingsSnapshot>("/api/settings/providers"),
  updateProviderSettings: (input: {
    openai_api_key?: string;
    clear_openai_api_key?: boolean;
    ollama_base_url?: string;
  }) =>
    request<ProviderSettingsUpdateResult>("/api/settings/providers", {
      method: "PATCH",
      body: JSON.stringify(input),
    }),
  pickRepository: () =>
    request<RepositorySnapshot>("/api/repositories/pick", {
      method: "POST",
    }),
  validateRepository: (path: string) =>
    request<RepositorySnapshot>("/api/repositories/validate", {
      method: "POST",
      body: JSON.stringify({ path }),
    }),
  listAudits: () =>
    request<{ audits: AuditRecord[] }>("/api/audits").then(
      (auditResponse) => auditResponse.audits,
    ),
  portfolio: () => request<PortfolioSummary>("/api/portfolio"),
  getAudit: (id: string) => request<AuditRecord>(`/api/audits/${id}`),
  createAudit: (input: {
    repository_path: string;
    provider: ProviderId;
    model_id: string;
    audit_type: AuditType;
    remote_source_consent: boolean;
  }) =>
    request<AuditRecord>("/api/audits", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  buildAgentPrompt: (auditId: string, findingId: string) =>
    request<AgentPrompt>(`/api/audits/${auditId}/findings/${findingId}/prompt`, {
      method: "POST",
    }),
  updateFinding: (auditId: string, findingId: string, input: FindingUpdate) =>
    request<Finding>(`/api/audits/${auditId}/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify(input),
    }),
  buildTicketHandoff: (auditId: string, findingId: string) =>
    request<TicketHandoff>(
      `/api/audits/${auditId}/findings/${findingId}/ticket-handoff?system=generic`,
    ),
  compareAudit: (auditId: string, baselineId?: string) => {
    const query = baselineId ? `?baseline_id=${encodeURIComponent(baselineId)}` : "";
    return request<AuditComparison>(`/api/audits/${auditId}/comparison${query}`);
  },
  verifyFinding: (auditId: string, findingId: string) =>
    request<VerificationAttempt>(
      `/api/audits/${auditId}/findings/${findingId}/verify`,
      { method: "POST" },
    ),
  listRuntimeCaptures: (repositoryPath?: string) => {
    const query = repositoryPath
      ? `?repository_path=${encodeURIComponent(repositoryPath)}`
      : "";
    return request<{ captures: RuntimeCapture[] }>(`/api/runtime-captures${query}`).then(
      (response) => response.captures,
    );
  },
  importRuntimeCapture: (input: {
    repository_path: string;
    filename: string;
    content: string;
    kind: RuntimeArtifactKind;
    build_mode: RuntimeBuildMode;
    flutter_version?: string;
    devtools_version?: string;
    dart_version?: string;
    label?: string;
  }) =>
    request<RuntimeCapture>("/api/runtime-captures/import", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  compareRuntimeCaptures: (baselineId: string, currentId: string) =>
    request<RuntimeCaptureComparison>(
      `/api/runtime-captures/compare?baseline_id=${encodeURIComponent(baselineId)}&current_id=${encodeURIComponent(currentId)}`,
    ),
};
