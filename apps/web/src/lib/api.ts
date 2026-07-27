import type {
  AuditRecord,
  FixProposal,
  ProviderCatalog,
  ProviderId,
  RepositorySnapshot,
  SetupStatus,
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
      (result) => result.providers,
    ),
  validateRepository: (path: string) =>
    request<RepositorySnapshot>("/api/repositories/validate", {
      method: "POST",
      body: JSON.stringify({ path }),
    }),
  listAudits: () =>
    request<{ audits: AuditRecord[] }>("/api/audits").then((result) => result.audits),
  getAudit: (id: string) => request<AuditRecord>(`/api/audits/${id}`),
  createAudit: (input: {
    repository_path: string;
    provider: ProviderId;
    model_id: string;
    remote_source_consent: boolean;
  }) =>
    request<AuditRecord>("/api/audits", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  proposeFix: (auditId: string, findingId: string) =>
    request<FixProposal>(`/api/audits/${auditId}/findings/${findingId}/fix`, {
      method: "POST",
    }),
  applyFix: (
    auditId: string,
    findingId: string,
    proposal: FixProposal,
    verificationCommands: string[],
  ) =>
    request(`/api/audits/${auditId}/findings/${findingId}/apply`, {
      method: "POST",
      body: JSON.stringify({
        approved: true,
        expected_head: proposal.expected_head,
        patch: proposal.patch,
        verification_commands: verificationCommands,
      }),
    }),
  rollbackFix: (auditId: string, findingId: string) =>
    request(`/api/audits/${auditId}/findings/${findingId}/rollback`, {
      method: "POST",
    }),
};

