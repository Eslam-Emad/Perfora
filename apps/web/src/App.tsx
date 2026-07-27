import {
  Activity,
  ArrowRight,
  Bot,
  Box,
  Check,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock3,
  Code2,
  Download,
  FileCode2,
  FolderGit2,
  Gauge,
  GitBranch,
  HardDrive,
  KeyRound,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  SearchCode,
  Settings,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Wrench,
  X,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./lib/api";
import type {
  AuditRecord,
  Finding,
  FixProposal,
  ModelInfo,
  ProviderCatalog,
  ProviderId,
  RepositorySnapshot,
  SetupStatus,
} from "./types";

type View = "setup" | "repositories" | "new-audit" | "workspace" | "settings";

const providerNames: Record<ProviderId, string> = {
  opencode: "OpenCode",
  ollama: "Ollama",
  openai: "OpenAI",
};

const providerDescriptions: Record<ProviderId, string> = {
  opencode: "Use your configured OpenCode providers and credentials.",
  ollama: "Run private analysis with models hosted on this machine.",
  openai: "Use the Responses API with structured, evidence-bound output.",
};

function App() {
  const [view, setView] = useState<View>("setup");
  const [setup, setSetup] = useState<SetupStatus | null>(null);
  const [setupLoading, setSetupLoading] = useState(true);
  const [setupError, setSetupError] = useState("");
  const [repository, setRepository] = useState<RepositorySnapshot | null>(null);
  const [audits, setAudits] = useState<AuditRecord[]>([]);
  const [activeAudit, setActiveAudit] = useState<AuditRecord | null>(null);

  const refreshSetup = useCallback(async () => {
    setSetupLoading(true);
    setSetupError("");
    try {
      setSetup(await api.setup());
    } catch (error) {
      setSetupError(error instanceof Error ? error.message : "Setup check failed");
    } finally {
      setSetupLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshSetup();
    void api.listAudits().then(setAudits).catch(() => undefined);
  }, [refreshSetup]);

  const refreshAudit = useCallback(async (auditId: string) => {
    const current = await api.getAudit(auditId);
    setActiveAudit(current);
    setAudits((items) => [current, ...items.filter((item) => item.id !== current.id)]);
  }, []);

  useEffect(() => {
    if (!activeAudit || ["completed", "partial", "failed", "cancelled"].includes(activeAudit.status)) {
      return;
    }
    const stream = new EventSource(`/api/audits/${activeAudit.id}/events`);
    stream.onmessage = () => void refreshAudit(activeAudit.id);
    stream.addEventListener("terminal", () => {
      void refreshAudit(activeAudit.id);
      stream.close();
    });
    stream.onerror = () => stream.close();
    return () => stream.close();
  }, [activeAudit?.id, activeAudit?.status, refreshAudit]);

  const openAudit = (audit: AuditRecord) => {
    setActiveAudit(audit);
    setRepository(audit.repository);
    setView("workspace");
  };

  return (
    <div className="app-shell">
      <Sidebar view={view} onNavigate={setView} />
      <main className="main-shell">
        <Topbar view={view} setup={setup} />
        <div className="content-shell">
          {view === "setup" && (
            <SetupView
              setup={setup}
              loading={setupLoading}
              error={setupError}
              onRefresh={refreshSetup}
              onContinue={() => setView("repositories")}
            />
          )}
          {view === "repositories" && (
            <RepositoriesView
              repository={repository}
              audits={audits}
              onValidated={setRepository}
              onNewAudit={() => setView("new-audit")}
              onOpenAudit={openAudit}
            />
          )}
          {view === "new-audit" && (
            <NewAuditView
              repository={repository}
              catalogs={setup?.providers ?? []}
              onBack={() => setView("repositories")}
              onCreated={(audit) => {
                setActiveAudit(audit);
                setAudits((items) => [audit, ...items]);
                setView("workspace");
              }}
            />
          )}
          {view === "workspace" && (
            <AuditWorkspace
              audit={activeAudit}
              onRefresh={() => activeAudit && refreshAudit(activeAudit.id)}
              onNewAudit={() => setView("new-audit")}
            />
          )}
          {view === "settings" && (
            <SettingsView setup={setup} onRefresh={refreshSetup} />
          )}
        </div>
      </main>
    </div>
  );
}

function Sidebar({ view, onNavigate }: { view: View; onNavigate: (view: View) => void }) {
  const items = [
    { id: "setup" as const, label: "Setup", icon: Gauge },
    { id: "repositories" as const, label: "Repositories", icon: FolderGit2 },
    { id: "new-audit" as const, label: "New audit", icon: Sparkles },
    { id: "workspace" as const, label: "Audit workspace", icon: SearchCode },
  ];
  return (
    <aside className="sidebar">
      <button className="brand" onClick={() => onNavigate("setup")}>
        <span className="brand-mark"><Activity size={21} /></span>
        <span>
          <strong>Perfora</strong>
          <small>Performance intelligence</small>
        </span>
      </button>
      <nav className="primary-nav" aria-label="Primary navigation">
        <p className="nav-label">Workspace</p>
        {items.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={view === id ? "nav-item active" : "nav-item"}
            onClick={() => onNavigate(id)}
          >
            <Icon size={18} />
            <span>{label}</span>
            {view === id && <span className="nav-dot" />}
          </button>
        ))}
      </nav>
      <div className="sidebar-spacer" />
      <div className="local-card">
        <div className="local-card-icon"><HardDrive size={18} /></div>
        <div>
          <strong>Local workspace</strong>
          <span>Source stays under your control</span>
        </div>
      </div>
      <button
        className={view === "settings" ? "nav-item active" : "nav-item"}
        onClick={() => onNavigate("settings")}
      >
        <Settings size={18} /> Settings
      </button>
      <div className="sidebar-footer">
        <span>v0.1 tracer</span><span className="status-dot" /> localhost
      </div>
    </aside>
  );
}

function Topbar({ view, setup }: { view: View; setup: SetupStatus | null }) {
  const labels: Record<View, string> = {
    setup: "Environment setup",
    repositories: "Repositories",
    "new-audit": "Create audit",
    workspace: "Audit workspace",
    settings: "Settings",
  };
  const readyProviders = setup?.providers.filter((provider) => provider.available).length ?? 0;
  return (
    <header className="topbar">
      <div className="breadcrumb">
        <span>Perfora</span><ChevronRight size={14} /><strong>{labels[view]}</strong>
      </div>
      <div className="topbar-actions">
        <span className="privacy-chip"><LockKeyhole size={14} /> localhost only</span>
        <span className="provider-chip"><Bot size={14} /> {readyProviders}/3 providers ready</span>
        <button className="avatar" aria-label="Local user">IS</button>
      </div>
    </header>
  );
}

function SetupView({
  setup,
  loading,
  error,
  onRefresh,
  onContinue,
}: {
  setup: SetupStatus | null;
  loading: boolean;
  error: string;
  onRefresh: () => void;
  onContinue: () => void;
}) {
  const ready = setup?.tools.filter((tool) => tool.available).length ?? 0;
  return (
    <section className="page">
      <PageHeading
        eyebrow="Local readiness"
        title="Make the invisible setup visible."
        description="Perfora checks every local dependency before an audit begins, so missing tools become clear actions—not failed jobs."
        action={
          <button className="button secondary" onClick={onRefresh} disabled={loading}>
            <RefreshCw className={loading ? "spin" : ""} size={16} /> Refresh health
          </button>
        }
      />
      {error && <Notice tone="danger" title="API unavailable">{error}</Notice>}
      <div className="hero-grid">
        <div className="readiness-card">
          <div className="readiness-ring" style={{ "--progress": `${(ready / 5) * 360}deg` } as React.CSSProperties}>
            <div><strong>{ready}/5</strong><span>tools ready</span></div>
          </div>
          <div>
            <p className="eyebrow">Environment score</p>
            <h2>{ready === 5 ? "Ready to investigate" : "A few tools need attention"}</h2>
            <p>This is setup readiness—not a performance score. Every status below is directly observed.</p>
          </div>
        </div>
        <div className="trust-card">
          <ShieldCheck size={24} />
          <div><strong>Evidence before inference</strong><span>Dart analysis establishes facts. Models explain and propose.</span></div>
          <div className="trust-divider" />
          <LockKeyhole size={24} />
          <div><strong>Private by default</strong><span>Remote source requires explicit consent and a context manifest.</span></div>
        </div>
      </div>
      <SectionTitle title="Toolchain" subtitle="Observed directly on this Mac" />
      <div className="tool-grid">
        {(setup?.tools ?? Array.from({ length: 5 })).map((tool, index) =>
          tool ? <ToolCard key={tool.id} tool={tool} /> : <div className="tool-card skeleton" key={index} />,
        )}
      </div>
      <SectionTitle title="Model providers" subtitle="One explicit model is recorded per audit" />
      <div className="provider-grid">
        {(setup?.providers ?? []).map((provider) => <ProviderCard key={provider.provider} provider={provider} />)}
      </div>
      <div className="footer-action">
        <div><strong>Next: add a Flutter repository</strong><span>Perfora only reads repositories you explicitly select.</span></div>
        <button className="button primary" onClick={onContinue}>Continue <ArrowRight size={17} /></button>
      </div>
    </section>
  );
}

function ToolCard({ tool }: { tool: SetupStatus["tools"][number] }) {
  const icons: Record<string, typeof Code2> = {
    git: GitBranch,
    dart: Code2,
    flutter: Layers3,
    opencode: TerminalSquare,
    ollama: Box,
  };
  const Icon = icons[tool.id] ?? Wrench;
  return (
    <article className="tool-card">
      <div className={tool.available ? "icon-tile success" : "icon-tile muted"}><Icon size={20} /></div>
      <div className="tool-title"><strong>{tool.label}</strong><StatusPill ready={tool.available} /></div>
      <p>{tool.detail}</p>
      <code>{tool.version ?? "Not detected"}</code>
    </article>
  );
}

function ProviderCard({ provider }: { provider: ProviderCatalog }) {
  return (
    <article className="provider-card">
      <div className="provider-card-top">
        <div className={`provider-logo ${provider.provider}`}>{provider.provider === "openai" ? <Sparkles /> : provider.provider === "ollama" ? <Box /> : <TerminalSquare />}</div>
        <StatusPill ready={provider.available} />
      </div>
      <h3>{providerNames[provider.provider]}</h3>
      <p>{providerDescriptions[provider.provider]}</p>
      <div className="provider-meta"><span>{provider.models.length} models</span><span>{provider.detail}</span></div>
    </article>
  );
}

function RepositoriesView({
  repository,
  audits,
  onValidated,
  onNewAudit,
  onOpenAudit,
}: {
  repository: RepositorySnapshot | null;
  audits: AuditRecord[];
  onValidated: (repository: RepositorySnapshot) => void;
  onNewAudit: () => void;
  onOpenAudit: (audit: AuditRecord) => void;
}) {
  const [path, setPath] = useState(repository?.path ?? "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const validate = async () => {
    setLoading(true);
    setError("");
    try {
      const result = await api.validateRepository(path);
      if (!result.valid) throw new Error(result.detail);
      onValidated(result);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Repository validation failed");
    } finally {
      setLoading(false);
    }
  };
  return (
    <section className="page">
      <PageHeading eyebrow="Source context" title="Connect a local Flutter repository." description="Perfora records the exact branch, commit, SDK context, and package fingerprint behind every finding." />
      <div className="repo-connect">
        <div className="connect-icon"><FolderGit2 size={28} /></div>
        <div className="connect-copy"><strong>Local repository path</strong><span>No cloning and no source upload during validation.</span></div>
        <div className="path-input"><input value={path} onChange={(event) => setPath(event.target.value)} placeholder="/Users/you/projects/flutter_app" /><button className="button primary" onClick={validate} disabled={!path || loading}>{loading ? <LoaderCircle className="spin" /> : <Plus />} Validate</button></div>
        {error && <p className="field-error"><CircleAlert size={15} /> {error}</p>}
      </div>
      {repository && (
        <article className="repository-card">
          <div className="repo-accent" />
          <div className="repo-main">
            <div className="repo-icon"><FileCode2 size={22} /></div>
            <div><p className="eyebrow">Validated Flutter repository</p><h2>{repository.name}</h2><code>{repository.path}</code></div>
          </div>
          <div className="repo-stats">
            <Metric label="Branch" value={repository.branch || "No branch"} icon={GitBranch} />
            <Metric label="Revision" value={repository.commit_sha?.slice(0, 8) || "Uncommitted"} icon={Code2} />
            <Metric label="Packages" value={String(repository.packages.length)} icon={Layers3} />
            <Metric label="Worktree" value={repository.clean ? "Clean" : "Has changes"} icon={repository.clean ? CircleCheck : CircleAlert} />
          </div>
          <div className="repo-actions"><span><ShieldCheck size={16} /> Fingerprint {repository.fingerprint?.slice(0, 12)}</span><button className="button primary" onClick={onNewAudit}><Sparkles size={16} /> New audit</button></div>
        </article>
      )}
      <SectionTitle title="Audit history" subtitle={`${audits.length} immutable run${audits.length === 1 ? "" : "s"}`} />
      <div className="audit-list">
        {audits.length === 0 ? <EmptyState icon={Clock3} title="No audits yet" description="Your first evidence trail will appear here." /> : audits.map((audit) => (
          <button className="audit-row" key={audit.id} onClick={() => onOpenAudit(audit)}>
            <span className={`audit-status ${audit.status}`}><Activity size={16} /></span>
            <span className="audit-row-main"><strong>{audit.repository.name}</strong><small>{new Date(audit.created_at).toLocaleString()}</small></span>
            <span><strong>{audit.findings.length}</strong><small>findings</small></span>
            <span><strong>{providerNames[audit.provider]}</strong><small>{audit.model_id}</small></span>
            <StatusPill ready={audit.status === "completed"} label={audit.status} />
            <ChevronRight size={17} />
          </button>
        ))}
      </div>
    </section>
  );
}

function NewAuditView({
  repository,
  catalogs,
  onBack,
  onCreated,
}: {
  repository: RepositorySnapshot | null;
  catalogs: ProviderCatalog[];
  onBack: () => void;
  onCreated: (audit: AuditRecord) => void;
}) {
  const compatibleModels = useMemo(() => catalogs.flatMap((catalog) => catalog.models.filter((model) => model.compatible)), [catalogs]);
  const [modelKey, setModelKey] = useState(compatibleModels[0] ? `${compatibleModels[0].provider}:${compatibleModels[0].id}` : "");
  const selected = compatibleModels.find((model) => `${model.provider}:${model.id}` === modelKey);
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const isRemote = selected?.locality !== "local";
  const create = async () => {
    if (!repository || !selected) return;
    setLoading(true);
    setError("");
    try {
      const audit = await api.createAudit({
        repository_path: repository.path,
        provider: selected.provider,
        model_id: selected.id,
        remote_source_consent: isRemote ? consent : false,
      });
      onCreated(audit);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not create audit");
    } finally {
      setLoading(false);
    }
  };
  if (!repository) return <section className="page"><EmptyState icon={FolderGit2} title="Add a repository first" description="A validated local Flutter repository is required." action={<button className="button primary" onClick={onBack}>Open repositories</button>} /></section>;
  return (
    <section className="page narrow">
      <PageHeading eyebrow="Immutable run configuration" title="Start an evidence-first audit." description="The selected model and repository revision are permanently attached to this run. Perfora never falls back silently." />
      <div className="step-card">
        <span className="step-number">1</span><div className="step-body"><h2>Repository revision</h2><p>Confirm the exact source snapshot to analyze.</p>
          <div className="selection-card"><FolderGit2 /><div><strong>{repository.name}</strong><code>{repository.path}</code></div><div className="selection-meta"><span>{repository.branch || "no branch"}</span><span>{repository.commit_sha?.slice(0, 8) || "no commit"}</span></div></div>
        </div>
      </div>
      <div className="step-card">
        <span className="step-number">2</span><div className="step-body"><h2>Analysis model</h2><p>Choose one discovered, compatible model.</p>
          <label className="select-label">Provider and model<select value={modelKey} onChange={(event) => setModelKey(event.target.value)}><option value="">Select a model</option>{catalogs.map((catalog) => <optgroup key={catalog.provider} label={`${providerNames[catalog.provider]} · ${catalog.available ? "ready" : "unavailable"}`}>{catalog.models.filter((model) => model.compatible).map((model) => <option key={`${catalog.provider}:${model.id}`} value={`${catalog.provider}:${model.id}`}>{model.label} · {model.locality}</option>)}</optgroup>)}</select></label>
          {selected && <div className="model-summary"><span className={`provider-logo mini ${selected.provider}`}><Bot /></span><div><strong>{selected.label}</strong><span>{providerNames[selected.provider]} · {selected.locality} · {selected.capability_status}</span></div><Check size={18} /></div>}
          {compatibleModels.length === 0 && <Notice tone="warning" title="No compatible model found">Configure OpenCode or Ollama, or refresh OpenAI model discovery in Settings.</Notice>}
        </div>
      </div>
      <div className="step-card">
        <span className="step-number">3</span><div className="step-body"><h2>Evidence and privacy</h2><p>The lifecycle rule pack covers Riverpod, Provider, Bloc/Cubit, and GetX.</p>
          <div className="rule-strip"><ShieldCheck /><div><strong>Deterministic lifecycle analysis</strong><span>Owned controllers, streams, timers, and workers are matched to cleanup hooks.</span></div><span className="rule-count">4 frameworks</span></div>
          {isRemote && <label className="consent-card"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /><span><strong>I approve evidence snippets for this remote provider</strong><small>Perfora redacts likely secrets and records the transmitted file manifest.</small></span></label>}
        </div>
      </div>
      {error && <Notice tone="danger" title="Audit could not start">{error}</Notice>}
      <div className="create-footer"><button className="button ghost" onClick={onBack}>Back</button><div><span>No silent model fallback</span><button className="button primary large" onClick={create} disabled={!selected || loading || (isRemote && !consent)}>{loading ? <LoaderCircle className="spin" /> : <Play />} Start audit</button></div></div>
    </section>
  );
}

function AuditWorkspace({ audit, onRefresh, onNewAudit }: { audit: AuditRecord | null; onRefresh: () => void; onNewAudit: () => void }) {
  const [selectedId, setSelectedId] = useState<string | null>(audit?.findings[0]?.id ?? null);
  useEffect(() => {
    if (audit?.findings.length && !audit.findings.some((finding) => finding.id === selectedId)) setSelectedId(audit.findings[0].id);
  }, [audit?.findings, selectedId]);
  if (!audit) return <section className="page"><EmptyState icon={SearchCode} title="No audit selected" description="Start or open an audit to inspect its evidence." action={<button className="button primary" onClick={onNewAudit}>Create audit</button>} /></section>;
  const selected = audit.findings.find((finding) => finding.id === selectedId) ?? audit.findings[0];
  const progress = audit.events.at(-1)?.progress ?? 0;
  return (
    <section className="workspace-page">
      <div className="workspace-header">
        <div><p className="eyebrow">{audit.repository.name} · {audit.repository.branch || "detached"}</p><h1>Lifecycle evidence audit</h1><div className="audit-meta"><span><Bot size={14} /> {providerNames[audit.provider]}/{audit.model_id}</span><span><GitBranch size={14} /> {audit.repository.commit_sha?.slice(0, 8) || "no commit"}</span><span><Clock3 size={14} /> {new Date(audit.created_at).toLocaleTimeString()}</span></div></div>
        <div className="workspace-actions"><button className="button secondary" onClick={onRefresh}><RefreshCw size={16} /> Refresh</button><ExportMenu audit={audit} /></div>
      </div>
      <div className="progress-band"><div className="progress-copy"><span className={`pulse ${audit.status}`} /> <strong>{audit.events.at(-1)?.message || audit.status}</strong><span>{progress}%</span></div><div className="progress-track"><span style={{ width: `${progress}%` }} /></div></div>
      <div className="evidence-summary">
        <Metric label="Confirmed findings" value={String(audit.findings.filter((finding) => finding.status === "confirmed").length)} icon={ShieldCheck} />
        <Metric label="High severity" value={String(audit.findings.filter((finding) => ["high", "critical"].includes(finding.severity)).length)} icon={Zap} />
        <Metric label="Files transmitted" value={String(audit.context_manifest.length)} icon={FileCode2} />
        <Metric label="Run status" value={audit.status} icon={Activity} />
      </div>
      {audit.error && <Notice tone={audit.status === "partial" ? "warning" : "danger"} title={audit.status === "partial" ? "Partial audit" : "Audit failed"}>{audit.error}</Notice>}
      <div className="investigation-grid">
        <aside className="findings-panel">
          <div className="panel-heading"><div><p className="eyebrow">Evidence queue</p><h2>Findings</h2></div><span>{audit.findings.length}</span></div>
          {audit.findings.length === 0 ? <div className="panel-empty"><LoaderCircle className={audit.status === "running" ? "spin" : ""} /><strong>{audit.status === "running" ? "Analyzing syntax trees" : "No lifecycle findings"}</strong></div> : audit.findings.map((finding) => <button key={finding.id} className={selected?.id === finding.id ? "finding-row selected" : "finding-row"} onClick={() => setSelectedId(finding.id)}><span className={`severity-mark ${finding.severity}`} /><div><span className="finding-framework">{finding.framework}</span><strong>{finding.title}</strong><small>{finding.file}:{finding.line}</small></div><span className="confidence">{Math.round(finding.confidence * 100)}%</span></button>)}
        </aside>
        <div className="detail-panel">
          {selected ? <FindingDetail finding={selected} audit={audit} onRefresh={onRefresh} /> : <EmptyState icon={SearchCode} title="Waiting for evidence" description="The deterministic analyzer is inspecting lifecycle ownership." />}
        </div>
      </div>
    </section>
  );
}

function FindingDetail({ finding, audit, onRefresh }: { finding: Finding; audit: AuditRecord; onRefresh: () => void }) {
  const [proposal, setProposal] = useState<FixProposal | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [applied, setApplied] = useState(false);
  const propose = async () => {
    setLoading(true); setError("");
    try { setProposal(await api.proposeFix(audit.id, finding.id)); } catch (reason) { setError(reason instanceof Error ? reason.message : "Fix generation failed"); } finally { setLoading(false); }
  };
  const apply = async () => {
    if (!proposal) return;
    setLoading(true); setError("");
    try { await api.applyFix(audit.id, finding.id, proposal, ["flutter analyze"]); setApplied(true); onRefresh(); } catch (reason) { setError(reason instanceof Error ? reason.message : "Fix application failed"); } finally { setLoading(false); }
  };
  const rollback = async () => {
    setLoading(true); setError("");
    try { await api.rollbackFix(audit.id, finding.id); setApplied(false); onRefresh(); } catch (reason) { setError(reason instanceof Error ? reason.message : "Rollback failed"); } finally { setLoading(false); }
  };
  return (
    <>
      <div className="detail-heading"><div><div className="finding-tags"><span className={`severity-pill ${finding.severity}`}>{finding.severity}</span><span className="confirmed-pill"><ShieldCheck size={13} /> {finding.status}</span><span>{finding.framework}</span></div><h2>{finding.title}</h2><code>{finding.file}:{finding.line} · {finding.symbol}</code></div><button className="button primary" onClick={propose} disabled={loading || audit.status === "partial"}>{loading ? <LoaderCircle className="spin" /> : <Wrench />} Generate fix</button></div>
      <div className="detail-section"><p className="eyebrow">Causal explanation</p><p className="lead-copy">{finding.model_explanation || finding.explanation}</p></div>
      <div className="detail-section"><p className="eyebrow">Deterministic evidence</p><div className="evidence-list">{finding.evidence.map((item) => <div key={item}><CircleCheck size={16} /><span>{item}</span></div>)}</div></div>
      <div className="detail-section recommendation"><div className="recommendation-icon"><Sparkles size={19} /></div><div><p className="eyebrow">Recommended change</p><p>{finding.recommendation}</p></div></div>
      <div className="context-manifest"><LockKeyhole size={16} /><span><strong>Context manifest:</strong> only {audit.context_manifest.length ? audit.context_manifest.join(", ") : "deterministic evidence"} was selected for model enrichment.</span></div>
      {error && <Notice tone="danger" title="Apply Fix">{error}</Notice>}
      {proposal && <div className="fix-review"><div className="fix-review-heading"><div><p className="eyebrow">Reviewed patch required</p><h3>{proposal.summary}</h3><span>Risk: {proposal.risk}</span></div><button className="icon-button" onClick={() => setProposal(null)}><X size={17} /></button></div><pre>{proposal.patch}</pre><div className="fix-actions"><span><GitBranch size={15} /> Will create perfora/fix-{finding.id.slice(0, 8)}</span>{applied ? <button className="button secondary danger" onClick={rollback} disabled={loading}><RotateCcw size={16} /> Roll back</button> : <button className="button primary" onClick={apply} disabled={loading}><ShieldCheck size={16} /> Approve & apply</button>}</div></div>}
    </>
  );
}

function SettingsView({ setup, onRefresh }: { setup: SetupStatus | null; onRefresh: () => void }) {
  return (
    <section className="page">
      <PageHeading eyebrow="Local control plane" title="Providers, privacy, and policy." description="Credentials stay in their native local stores. Perfora records configuration metadata, never secret values." action={<button className="button secondary" onClick={onRefresh}><RefreshCw size={16} /> Test connections</button>} />
      <div className="settings-grid">
        <div className="settings-main">
          <SectionTitle title="Model providers" subtitle="Dynamic discovery, explicit selection" />
          {(setup?.providers ?? []).map((provider) => <div className="setting-row" key={provider.provider}><div className={`provider-logo ${provider.provider}`}>{provider.provider === "openai" ? <Sparkles /> : provider.provider === "ollama" ? <Box /> : <TerminalSquare />}</div><div><strong>{providerNames[provider.provider]}</strong><span>{provider.detail}</span></div><div className="setting-row-tail"><StatusPill ready={provider.available} /><span>{provider.models.length} models</span></div></div>)}
          <SectionTitle title="Verification policy" subtitle="Commands are shown before execution" />
          {["dart analyze", "flutter analyze", "flutter test"].map((command) => <div className="command-row" key={command}><TerminalSquare size={16} /><code>{command}</code><span><Check size={14} /> built-in safe</span></div>)}
        </div>
        <aside className="privacy-panel">
          <div className="privacy-illustration"><ShieldCheck size={38} /><span className="orbit one" /><span className="orbit two" /></div>
          <p className="eyebrow">Privacy posture</p><h2>Zero automatic telemetry.</h2><p>Repository contents, prompts, responses, and audit logs remain local except for evidence explicitly approved for a remote model.</p>
          <ul><li><Check /> Secrets redacted before model context</li><li><Check /> Unknown routing treated as remote</li><li><Check /> Context manifest saved per audit</li><li><Check /> No silent provider fallback</li></ul>
          <div className="key-status"><KeyRound size={17} /><div><strong>OpenAI credential</strong><span>{setup?.providers.find((item) => item.provider === "openai")?.available ? "Configured in local environment" : "Not configured"}</span></div></div>
        </aside>
      </div>
    </section>
  );
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{description}</p></div>{action}</div>;
}

function SectionTitle({ title, subtitle }: { title: string; subtitle: string }) {
  return <div className="section-title"><h2>{title}</h2><span>{subtitle}</span></div>;
}

function StatusPill({ ready, label }: { ready: boolean; label?: string }) {
  return <span className={ready ? "status-pill ready" : "status-pill unavailable"}>{ready ? <CircleCheck size={13} /> : <CircleAlert size={13} />}{label ?? (ready ? "Ready" : "Unavailable")}</span>;
}

function Metric({ label, value, icon: Icon }: { label: string; value: string; icon: typeof Activity }) {
  return <div className="metric"><span className="metric-icon"><Icon size={17} /></span><div><small>{label}</small><strong>{value}</strong></div></div>;
}

function Notice({ tone, title, children }: { tone: "warning" | "danger"; title: string; children: React.ReactNode }) {
  return <div className={`notice ${tone}`}><CircleAlert size={19} /><div><strong>{title}</strong><span>{children}</span></div></div>;
}

function EmptyState({ icon: Icon, title, description, action }: { icon: typeof Activity; title: string; description: string; action?: React.ReactNode }) {
  return <div className="empty-state"><span><Icon size={24} /></span><h2>{title}</h2><p>{description}</p>{action}</div>;
}

function ExportMenu({ audit }: { audit: AuditRecord }) {
  return <div className="export-group"><Download size={16} />{(["html", "json", "sarif"] as const).map((format) => <a key={format} href={`/api/audits/${audit.id}/export?format=${format}`} download>{format.toUpperCase()}</a>)}</div>;
}

export default App;
