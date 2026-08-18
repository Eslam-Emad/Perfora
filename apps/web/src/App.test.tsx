import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type {
  AuditRecord,
  Finding,
  ProviderSettingsSnapshot,
  VerificationAttempt,
} from "./types";

const flutterProject = {
  path: "/Users/islam/projects/sample_flutter",
  name: "sample_flutter",
  valid: true,
  detail: "Flutter repository",
  is_flutter: true,
  is_git: true,
  branch: "main",
  commit_sha: "1234567890",
  clean: true,
  fingerprint: "abc123",
  packages: ["sample_flutter"],
};

const missingProject = {
  ...flutterProject,
  path: "/Users/islam/projects/missing_flutter",
  name: "missing_flutter",
  valid: false,
  detail: "Directory does not exist",
};

const setup = {
  tools: [],
  providers: [
    {
      provider: "ollama",
      available: true,
      detail: "Ollama ready",
      models: [
        {
          provider: "ollama",
          id: "qwen2.5-coder:7b",
          label: "qwen2.5-coder:7b",
          available: true,
          compatible: true,
          capability_status: "compatible",
          locality: "local",
          metadata: {},
        },
      ],
    },
  ],
};

function jsonResponse(body: unknown) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

function errorResponse(status: number, detail: string) {
  return Promise.resolve(
    new Response(JSON.stringify({ detail }), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

beforeEach(() => {
  window.localStorage.clear();
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/api/setup")) return jsonResponse(setup);
      if (path.endsWith("/api/repositories/validate")) return jsonResponse(flutterProject);
      if (path.includes("/api/runtime-captures")) return jsonResponse({ captures: [] });
      return jsonResponse({ audits: [] });
    }),
  );
});

describe("Perfora shell", () => {
  it("renders the local-first product identity", async () => {
    render(<App />);
    expect(await screen.findByText("0/3 providers ready")).toBeInTheDocument();
    expect(screen.getAllByText("Perfora")).toHaveLength(2);
    expect(screen.getByText("Make the invisible setup visible.")).toBeInTheDocument();
    expect(screen.getByText("localhost only")).toBeInTheDocument();
  });

  it("lets the user configure OpenAI and Ollama without reading the saved key back", async () => {
    const requests: Array<Record<string, unknown>> = [];
    let providerSettings: ProviderSettingsSnapshot = {
      openai: { configured: false, source: "none" },
      ollama: {
        base_url: "http://127.0.0.1:11434",
        source: "default",
        locality: "local",
      },
    };
    vi.mocked(fetch).mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith("/api/setup")) return jsonResponse(setup);
      if (path.endsWith("/api/settings/providers") && init?.method === "PATCH") {
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        requests.push(body);
        if (body.openai_api_key) {
          providerSettings = {
            ...providerSettings,
            openai: { configured: true, source: "settings" },
          };
        }
        if (body.ollama_base_url) {
          providerSettings = {
            ...providerSettings,
            ollama: {
              base_url: String(body.ollama_base_url),
              source: "settings",
              locality: "remote",
            },
          };
        }
        return jsonResponse({ settings: providerSettings, providers: setup.providers });
      }
      if (path.endsWith("/api/settings/providers")) return jsonResponse(providerSettings);
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Settings" }));

    const keyInput = await screen.findByLabelText("OpenAI API key");
    expect(keyInput).toHaveAttribute("type", "password");
    fireEvent.change(keyInput, { target: { value: "sk-test-ui-owned-key-0123456789" } });
    fireEvent.click(screen.getByRole("button", { name: "Save OpenAI key" }));

    await waitFor(() => expect(requests[0]).toEqual({ openai_api_key: "sk-test-ui-owned-key-0123456789" }));
    expect(keyInput).toHaveValue("");
    expect(screen.queryByText("sk-test-ui-owned-key-0123456789")).not.toBeInTheDocument();
    expect(screen.getByText("OpenAI key saved. Provider availability has been refreshed.")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Ollama base URL"), {
      target: { value: "https://ollama.example.test:11434" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Ollama endpoint" }));

    await waitFor(() => expect(requests[1]).toEqual({ ollama_base_url: "https://ollama.example.test:11434" }));
    expect(screen.getByText(/This endpoint is remote/)).toBeInTheDocument();
  });

  it("renders imported runtime evidence with provenance and trace references", async () => {
    const now = new Date().toISOString();
    const capture = {
      id: "runtime-1",
      record_version: 1,
      repository: flutterProject,
      label: "Checkout scroll — profile",
      kind: "frame_timing",
      reliability: "trusted",
      provenance: {
        filename: "scrolling_timeline.json",
        sha256: `sha256:${"a".repeat(64)}`,
        artifact_format: "Flutter TimelineSummary JSON",
        build_mode: "profile",
        build_mode_source: "artifact",
        flutter_version: "3.35.0",
        devtools_version: "2.48.0",
        imported_at: now,
      },
      metrics: { frame_count: 54, janky_frame_count: 2, worst_frame_build_time_ms: 21 },
      metric_units: { frame_count: "count", janky_frame_count: "count", worst_frame_build_time_ms: "ms" },
      breakdowns: {},
      evidence: [{
        id: "evidence:frame-1",
        kind: "frame",
        name: "UI frame",
        trace_reference: "$.frame_build_times[7]",
        duration_us: 21000,
        value: 21,
        unit: "ms",
        details: { budget_ms: 16.67 },
      }],
      findings: [{
        id: "runtime-finding-1",
        rule_id: "runtime.frame.jank",
        rule_version: "1.0.0",
        title: "Observed frames exceeded the 60 Hz frame budget",
        severity: "medium",
        confidence: 0.98,
        explanation: "The imported frame timing artifact contains UI work longer than 16.67 ms.",
        recommendation: "Inspect the linked frame in DevTools.",
        evidence_ids: ["evidence:frame-1"],
        observed: true,
      }],
      warnings: [],
      created_at: now,
    };
    vi.mocked(fetch).mockImplementation((input) => {
      const path = String(input);
      if (path.endsWith("/api/setup")) return jsonResponse(setup);
      if (path.includes("/api/runtime-captures")) return jsonResponse({ captures: [capture] });
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Runtime evidence" }));

    expect(await screen.findByText("Import real Flutter runtime evidence.")).toBeInTheDocument();
    expect(screen.getAllByText("Checkout scroll — profile").length).toBeGreaterThan(0);
    expect(screen.getByText("Flutter TimelineSummary JSON · scrolling_timeline.json")).toBeInTheDocument();
    expect(screen.getByText("Observed frames exceeded the 60 Hz frame budget")).toBeInTheDocument();
    expect(screen.getByText("$.frame_build_times[7]")).toBeInTheDocument();
    expect(screen.getByText(/never an invented overall performance score/i)).toBeInTheDocument();
  });

  it("renders local portfolio governance and recurrence evidence", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const path = String(input);
      if (path.endsWith("/api/setup")) return jsonResponse(setup);
      if (path.endsWith("/api/portfolio")) return jsonResponse({
        generated_at: new Date().toISOString(),
        scope: "latest local audit per repository and audit type",
        totals: {
          repositories: 1,
          audits: 4,
          open_findings: 3,
          high_or_critical: 2,
          verified_resolved: 5,
          recurrences: 1,
          governance_issues: 2,
        },
        repositories: [{
          path: flutterProject.path,
          name: flutterProject.name,
          latest_audit_at: new Date().toISOString(),
          audit_count: 4,
          open_findings: 3,
          high_or_critical: 2,
          verified_resolved: 5,
          recurrences: 1,
          governance_issues: 2,
          governance: { unassigned_high_or_critical: 1, resolved_not_verified: 1 },
        }],
        owners: [{ owner: "Application security", open: 2, overdue: 1 }],
        trends: [{
          audit_id: "audit-4",
          repository: flutterProject.name,
          audit_type: "security",
          created_at: new Date().toISOString(),
          total: 3,
          new: 1,
          regressed: 1,
          verified_resolved: 0,
        }],
      });
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Portfolio" }));

    expect(await screen.findByText("Govern risk across repositories.")).toBeInTheDocument();
    expect(screen.getByText("Application security")).toBeInTheDocument();
    expect(screen.getByText(/4 audits/)).toBeInTheDocument();
    expect(screen.getByText("3 total · 1 regressed")).toBeInTheDocument();
    expect(screen.getByText(/No account or external issue system is contacted/)).toBeInTheDocument();
  });

  it("saves a static project path and requires an explicit model choice", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));

    fireEvent.change(screen.getByLabelText("Static project path"), {
      target: { value: flutterProject.path },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add path" }));

    expect(await screen.findByText("Validated Flutter repository")).toBeInTheDocument();
    expect(window.localStorage.getItem("perfora.projects")).toContain(flutterProject.path);

    fireEvent.click(screen.getAllByRole("button", { name: "New audit" }).at(-1)!);
    expect(screen.getByRole("button", { name: /Ollama 1 models/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start audit" })).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: /Ollama 1 models/ }));
    fireEvent.change(screen.getByLabelText("Model"), {
      target: { value: "qwen2.5-coder:7b" },
    });

    expect(screen.getByText("qwen2.5-coder:7b")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start audit" })).toBeEnabled();
  });

  it("creates a security audit with the selected security rule pack", async () => {
    let createdBody: Record<string, unknown> | undefined;
    vi.mocked(fetch).mockImplementation((input, init) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/api/repositories/validate")) {
        return jsonResponse(flutterProject);
      }
      if (requestPath.endsWith("/api/audits") && init?.method === "POST") {
        createdBody = JSON.parse(String(init.body)) as Record<string, unknown>;
        return jsonResponse({
          id: "security-audit",
          repository: flutterProject,
          provider: "ollama",
          model_id: "qwen2.5-coder:7b",
          audit_type: "security",
          model_metadata: {},
          status: "completed",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          findings: [],
          events: [],
          context_manifest: [],
        });
      }
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.change(screen.getByLabelText("Static project path"), {
      target: { value: flutterProject.path },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add path" }));
    await screen.findByText("Validated Flutter repository");
    fireEvent.click(screen.getAllByRole("button", { name: "New audit" }).at(-1)!);
    fireEvent.click(screen.getByRole("button", { name: /Application security/ }));

    expect(screen.getByText("5 rules")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Ollama 1 models/ }));
    fireEvent.change(screen.getByLabelText("Model"), {
      target: { value: "qwen2.5-coder:7b" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Start audit" }));

    expect(await screen.findByText("Security evidence audit")).toBeInTheDocument();
    expect(createdBody?.audit_type).toBe("security");
  });

  it("copies a complete redacted finding prompt without generating a fix", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const audit: AuditRecord = {
      id: "security-audit",
      repository: flutterProject,
      provider: "ollama",
      model_id: "qwen2.5-coder:7b",
      audit_type: "security",
      model_metadata: {},
      status: "completed",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      findings: [{
        id: "finding-1",
        audit_id: "security-audit",
        fingerprint: "sha256:finding-1",
        rule_id: "network.cleartext_endpoint",
        rule_version: "1.0.0",
        title: "Cleartext HTTP endpoint is embedded in source",
        severity: "high",
        confidence: 0.98,
        status: "confirmed",
        file: "lib/config.dart",
        line: 12,
        symbol: "baseUrl",
        framework: "Dart",
        evidence: ["A cleartext endpoint was found."],
        explanation: "Traffic may be intercepted.",
        recommendation: "Use HTTPS.",
        control_group: "MASVS-NETWORK",
        platforms: ["Dart", "Android", "iOS"],
        standards: [{
          id: "MASVS-NETWORK-1",
          title: "Secure network traffic",
          url: "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/",
        }],
        detection_limitations: ["Only literal endpoints are detected."],
        manual_verification: ["Inspect release traffic on a test proxy."],
        false_positive_guidance: "Prove the endpoint cannot enter a release build.",
        model_enrichment: {
          provider: "ollama",
          model_id: "qwen2.5-coder:7b",
          explanation: "The model agrees with the observed transport risk.",
          recommendation: "Confirm the replacement endpoint before release.",
          generated_at: new Date().toISOString(),
        },
        triage_status: "new",
        comparison_status: "new",
        notes: [],
        status_history: [],
      }],
      events: [{
        sequence: 1,
        type: "completed",
        message: "Audit completed",
        progress: 100,
        created_at: new Date().toISOString(),
      }],
      context_manifest: ["lib/config.dart"],
      analyzer_version: "0.2.0",
      rule_pack: { id: "security", version: "1.0.0" },
      scan_coverage: {
        files_discovered: 4,
        files_scanned: 3,
        files_skipped: 1,
        scanned_by_type: { dart: 3 },
        skipped_by_reason: { generated_source: 1 },
        rules_executed: ["security.insecure_transport"],
        coverage_by_platform: { dart: 3, android: 0, ios: 0 },
        rules_by_control_group: { "MASVS-NETWORK": ["security.insecure_transport"] },
      },
      dependency_inventory: {
        components: [{
          bom_ref: "urn:perfora:firebase",
          name: "firebase_analytics",
          version: "12.0.0",
          ecosystem: "pub",
          source_file: "pubspec.lock",
          scope: "required",
          direct: true,
          purl: "pkg:pub/firebase_analytics@12.0.0",
          privacy_category: "analytics",
          privacy_sensitive: true,
        }],
        manifests: ["pubspec.lock"],
        coverage_by_ecosystem: { pub: 1 },
        license_counts: { unknown: 1 },
        privacy_sdk_counts: { analytics: 1 },
        vulnerability_matching: "not_requested",
      },
    };
    const handoffPrompt = "# Resolve this Perfora finding\nAll finding details";
    let currentAudit = audit;
    let updateBody: Record<string, unknown> | undefined;
    vi.mocked(fetch).mockImplementation((input, init) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/prompt")) {
        return jsonResponse({
          audit_id: audit.id,
          finding_id: audit.findings[0].id,
          prompt: handoffPrompt,
          redacted: true,
          generated_at: new Date().toISOString(),
        });
      }
      if (requestPath.includes("/ticket-handoff?system=generic")) {
        return jsonResponse({
          system: "generic",
          title: "[Perfora][HIGH] Cleartext HTTP endpoint is embedded in source",
          body: "## Perfora finding\nComplete redacted ticket body",
          labels: ["perfora", "high", "security"],
          finding_id: audit.findings[0].id,
          audit_id: audit.id,
          redacted: true,
          automatic_creation: false,
        });
      }
      if (requestPath.endsWith("/comparison")) {
        return jsonResponse({
          current_audit_id: audit.id,
          new_finding_ids: [audit.findings[0].id],
          unchanged_finding_ids: [],
          regressed_finding_ids: [],
          severity_changes: [],
          resolved_findings: [],
          dependency_changes: { added: [], removed: [], updated: [] },
        });
      }
      if (requestPath.endsWith(`/findings/${audit.findings[0].id}`) && init?.method === "PATCH") {
        updateBody = JSON.parse(String(init.body)) as Record<string, unknown>;
        const updatedFinding: Finding = {
          ...audit.findings[0],
          triage_status: updateBody.triage_status as Finding["triage_status"],
          owner: String(updateBody.owner),
          disposition_reason: String(updateBody.disposition_reason),
          notes: [{ id: "note-1", body: String(updateBody.note), created_at: new Date().toISOString() }],
          status_history: [{
            from_status: "new",
            to_status: updateBody.triage_status as Finding["triage_status"],
            reason: String(updateBody.disposition_reason),
            changed_at: new Date().toISOString(),
          }],
        };
        currentAudit = { ...audit, findings: [updatedFinding] };
        return jsonResponse(updatedFinding);
      }
      if (requestPath.endsWith(`/api/audits/${audit.id}`)) return jsonResponse(currentAudit);
      return jsonResponse({ audits: [audit] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.click(await screen.findByRole("button", { name: /sample_flutter Application security/ }));
    fireEvent.click(screen.getByRole("button", { name: "Copy prompt" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(handoffPrompt));
    expect(screen.getByRole("button", { name: "Copied" })).toBeInTheDocument();
    expect(screen.queryByText("Generate fix")).not.toBeInTheDocument();
    expect(screen.getByText("Traffic may be intercepted.")).toBeInTheDocument();
    expect(screen.getByText(/The model agrees with the observed transport risk/)).toBeInTheDocument();
    expect(screen.getByText(/discovered 4, scanned 3, skipped 1/)).toBeInTheDocument();
    expect(screen.getByText("Standards mapping · MASVS-NETWORK")).toBeInTheDocument();
    expect(screen.getByText("Only literal endpoints are detected.")).toBeInTheDocument();
    expect(screen.getByText("Inspect release traffic on a test proxy.")).toBeInTheDocument();
    expect(screen.getByText(/1 components · 1 manifests/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "SBOM" })).toHaveAttribute(
      "href",
      "/api/audits/security-audit/export?format=cyclonedx",
    );
    expect(screen.getByRole("link", { name: "Evidence ZIP" })).toHaveAttribute(
      "href",
      "/api/audits/security-audit/export?format=evidence",
    );
    expect(screen.getByText("Baseline comparison")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy ticket" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(
      "[Perfora][HIGH] Cleartext HTTP endpoint is embedded in source\n\n## Perfora finding\nComplete redacted ticket body\n\nLabels: perfora, high, security",
    ));
    expect(screen.getByRole("button", { name: "Ticket copied" })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Triage status"), { target: { value: "risk_accepted" } });
    fireEvent.change(screen.getByLabelText("Finding owner"), { target: { value: "Security team" } });
    fireEvent.change(screen.getByLabelText("Disposition reason"), { target: { value: "Compensating control documented" } });
    fireEvent.change(screen.getByLabelText("Finding note"), { target: { value: "Review before release" } });
    fireEvent.click(screen.getByRole("button", { name: "Save triage" }));

    await screen.findByRole("button", { name: "Saved" });
    expect(updateBody).toMatchObject({
      triage_status: "risk_accepted",
      owner: "Security team",
      disposition_reason: "Compensating control documented",
      note: "Review before release",
    });
  });

  it("verifies a resolved finding and renders deterministic proof", async () => {
    const now = new Date().toISOString();
    const verificationAudit: AuditRecord = {
      id: "verification-audit",
      repository: flutterProject,
      provider: "ollama",
      model_id: "qwen2.5-coder:7b",
      audit_type: "security",
      model_metadata: {},
      status: "completed",
      created_at: now,
      updated_at: now,
      events: [{ sequence: 1, type: "completed", message: "Audit completed", progress: 100, created_at: now }],
      context_manifest: [],
      analyzer_version: "0.3.0",
      rule_pack: { id: "security", version: "1.0.0" },
      scan_coverage: {
        files_discovered: 1,
        files_scanned: 1,
        files_skipped: 0,
        scanned_by_type: { dart: 1 },
        skipped_by_reason: {},
        rules_executed: ["security.insecure_transport"],
        scanned_files: ["lib/config.dart"],
        skipped_files_by_reason: {},
      },
      findings: [{
        id: "verification-finding",
        audit_id: "verification-audit",
        fingerprint: "sha256:verification",
        rule_id: "security.insecure_transport",
        rule_version: "1.0.0",
        title: "Cleartext endpoint",
        severity: "high",
        confidence: 0.98,
        status: "confirmed",
        file: "lib/config.dart",
        line: 7,
        symbol: "example.com",
        framework: "Dart",
        evidence: ["A cleartext endpoint was found."],
        explanation: "Traffic is not encrypted.",
        recommendation: "Use HTTPS.",
        triage_status: "resolved",
        notes: [],
        status_history: [],
        verification_attempts: [],
      }],
    };
    const attempt: VerificationAttempt = {
      id: "attempt-1",
      outcome: "verified_resolved",
      message: "The rule scanned the source and no longer reports the finding",
      started_at: now,
      completed_at: now,
      repository: flutterProject,
      analyzer_version: "0.3.0",
      rule_pack: { id: "security", version: "1.0.0" },
      scan_coverage: verificationAudit.scan_coverage!,
      rule_executed: true,
      source_present: true,
      file_scanned: true,
      observed_evidence: [],
    };
    let currentAudit = verificationAudit;
    let verificationCalled = false;
    vi.mocked(fetch).mockImplementation((input, init) => {
      const path = String(input);
      if (path.endsWith("/api/setup")) return jsonResponse(setup);
      if (path.endsWith("/comparison")) return jsonResponse({ current_audit_id: verificationAudit.id, new_finding_ids: [], unchanged_finding_ids: [], regressed_finding_ids: [], severity_changes: [], resolved_findings: [] });
      if (path.endsWith("/verify") && init?.method === "POST") {
        verificationCalled = true;
        currentAudit = {
          ...verificationAudit,
          findings: [{
            ...verificationAudit.findings[0],
            triage_status: "verified_resolved",
            verification_attempts: [attempt],
          }],
        };
        return jsonResponse(attempt);
      }
      if (path.endsWith(`/api/audits/${verificationAudit.id}`)) return jsonResponse(currentAudit);
      return jsonResponse({ audits: [verificationAudit] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.click(await screen.findByRole("button", { name: /sample_flutter Application security/ }));
    const verifyButton = screen.getByRole("button", { name: "Verify resolution" });
    expect(verifyButton).toBeEnabled();
    fireEvent.click(verifyButton);

    expect(await screen.findByText("The rule scanned the source and no longer reports the finding")).toBeInTheDocument();
    expect(screen.getByText("Rule executed")).toBeInTheDocument();
    expect(screen.getByText("Source scanned")).toBeInTheDocument();
    expect(verificationCalled).toBe(true);
  });

  it("revalidates a saved project and keeps its error beside that control", async () => {
    window.localStorage.setItem(
      "perfora.projects",
      JSON.stringify([flutterProject, { ...missingProject, valid: true }]),
    );
    vi.mocked(fetch).mockImplementation((input, init) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/api/repositories/validate")) {
        const request = JSON.parse(String(init?.body)) as { path: string };
        return jsonResponse(request.path === missingProject.path ? missingProject : flutterProject);
      }
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.change(screen.getByLabelText("Saved projects"), {
      target: { value: missingProject.path },
    });

    const message = await screen.findByRole("alert");
    expect(message).toHaveTextContent("Directory does not exist");
    expect(message).toHaveAttribute("data-source", "saved");
    expect(screen.queryByText("missing_flutter", { selector: ".repo-main h2" })).not.toBeInTheDocument();
  });

  it("does not trust cached repository metadata after a reload", async () => {
    window.localStorage.setItem(
      "perfora.projects",
      JSON.stringify([{ ...missingProject, valid: true }]),
    );

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));

    expect(screen.queryByText("Validated Flutter repository")).not.toBeInTheDocument();
    expect(screen.getByRole("option", { name: /missing_flutter/ })).toBeInTheDocument();
  });

  it("lets the user remove a saved project that no longer exists", async () => {
    window.localStorage.setItem(
      "perfora.projects",
      JSON.stringify([{ ...missingProject, valid: true }]),
    );
    vi.mocked(fetch).mockImplementation((input) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/api/repositories/validate")) return jsonResponse(missingProject);
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.change(screen.getByLabelText("Saved projects"), {
      target: { value: missingProject.path },
    });
    await screen.findByRole("alert");
    fireEvent.click(screen.getByRole("button", { name: "Remove saved project" }));

    expect(screen.queryByRole("option", { name: /missing_flutter/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await waitFor(() => expect(window.localStorage.getItem("perfora.projects")).toBe("[]"));
  });

  it("treats cancelling the native folder picker as a neutral action", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/api/repositories/pick")) {
        return errorResponse(409, "Folder selection was cancelled");
      }
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.click(screen.getByRole("button", { name: "Browse…" }));

    await waitFor(() => expect(screen.getByRole("button", { name: "Browse…" })).toBeEnabled());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("clears a manual-path error as soon as the user corrects the input", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/api/repositories/validate")) return jsonResponse(missingProject);
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    const pathInput = screen.getByLabelText("Static project path");
    fireEvent.change(pathInput, { target: { value: missingProject.path } });
    fireEvent.click(screen.getByRole("button", { name: "Add path" }));

    const message = await screen.findByRole("alert");
    expect(message).toHaveAttribute("data-source", "path");
    fireEvent.change(pathInput, { target: { value: flutterProject.path } });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("ignores malformed saved-project data instead of crashing the picker", async () => {
    window.localStorage.setItem(
      "perfora.projects",
      JSON.stringify({ path: flutterProject.path }),
    );

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));

    expect(screen.getByRole("option", { name: "No saved projects yet" })).toBeInTheDocument();
  });

  it("supports keyboard submission for a pasted project path", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.change(screen.getByLabelText("Static project path"), {
      target: { value: flutterProject.path },
    });
    fireEvent.submit(screen.getByRole("form", { name: "Add project by path" }));

    expect(await screen.findByText("Validated Flutter repository")).toBeInTheDocument();
  });

  it("can recheck a saved project after its directory becomes available", async () => {
    const recoveredProject = { ...flutterProject, path: missingProject.path, name: missingProject.name };
    let repositoryAvailable = false;
    window.localStorage.setItem(
      "perfora.projects",
      JSON.stringify([{ ...missingProject, valid: true }]),
    );
    vi.mocked(fetch).mockImplementation((input) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/api/repositories/validate")) {
        return jsonResponse(repositoryAvailable ? recoveredProject : missingProject);
      }
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.change(screen.getByLabelText("Saved projects"), {
      target: { value: missingProject.path },
    });
    await screen.findByRole("alert");
    repositoryAvailable = true;
    fireEvent.click(screen.getByRole("button", { name: "Recheck saved project" }));

    expect(await screen.findByText("Validated Flutter repository")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("revalidates project changes made from the new-audit screen", async () => {
    window.localStorage.setItem(
      "perfora.projects",
      JSON.stringify([{ ...missingProject, valid: true }]),
    );
    vi.mocked(fetch).mockImplementation((input, init) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/api/repositories/validate")) {
        const request = JSON.parse(String(init?.body)) as { path: string };
        return jsonResponse(request.path === missingProject.path ? missingProject : flutterProject);
      }
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    fireEvent.change(screen.getByLabelText("Static project path"), {
      target: { value: flutterProject.path },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add path" }));
    await screen.findByText("Validated Flutter repository");
    fireEvent.click(screen.getAllByRole("button", { name: "New audit" }).at(-1)!);
    fireEvent.change(screen.getByLabelText("Project"), {
      target: { value: missingProject.path },
    });

    const message = await screen.findByRole("alert");
    expect(message).toHaveAttribute("data-source", "audit-project");
    expect(screen.getByText("sample_flutter", { selector: ".selection-card strong" })).toBeInTheDocument();
  });

  it("discards an old validation error after the path is cleared", async () => {
    let resolveValidation!: (response: Response) => void;
    const pendingValidation = new Promise<Response>((resolve) => {
      resolveValidation = resolve;
    });
    vi.mocked(fetch).mockImplementation((input) => {
      const requestPath = String(input);
      if (requestPath.endsWith("/api/setup")) return jsonResponse(setup);
      if (requestPath.endsWith("/api/repositories/validate")) return pendingValidation;
      return jsonResponse({ audits: [] });
    });

    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Repositories" }));
    const pathInput = screen.getByLabelText("Static project path");
    fireEvent.change(pathInput, { target: { value: "relative/project" } });
    fireEvent.click(screen.getByRole("button", { name: "Add path" }));
    fireEvent.change(pathInput, { target: { value: "" } });
    resolveValidation(
      new Response(
        JSON.stringify({
          ...missingProject,
          path: "relative/project",
          detail: "Repository path must be absolute",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await waitFor(() => expect(screen.getByRole("button", { name: "Browse…" })).toBeEnabled());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
