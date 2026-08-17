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
  Copy,
  Download,
  FileCode2,
  FolderOpen,
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
  SearchCode,
  Settings,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Wrench,
  X,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./lib/api";
import type {
  AuditComparison,
  AuditRecord,
  AuditType,
  Finding,
  FindingUpdate,
  ModelInfo,
  ProviderCatalog,
  ProviderId,
  RepositorySnapshot,
  SetupStatus,
  TriageStatus,
} from "./types";

type View = "setup" | "repositories" | "new-audit" | "workspace" | "settings";
type PickerIssue = { source: "saved" | "path"; message: string };

const PROJECTS_STORAGE_KEY = "perfora.projects";

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

const auditTypeNames: Record<AuditType, string> = {
  performance: "Lifecycle performance",
  security: "Application security",
};

function auditTypeOf(audit: AuditRecord): AuditType {
  return audit.audit_type ?? "performance";
}

function loadSavedProjects(): RepositorySnapshot[] {
  try {
    const saved = window.localStorage.getItem(PROJECTS_STORAGE_KEY);
    const parsed: unknown = saved ? JSON.parse(saved) : [];
    if (!Array.isArray(parsed)) return [];
    const seenPaths = new Set<string>();
    return parsed.filter((value): value is RepositorySnapshot => {
      if (!value || typeof value !== "object") return false;
      const project = value as Partial<RepositorySnapshot>;
      if (
        typeof project.path !== "string"
        || !project.path.trim()
        || typeof project.name !== "string"
        || typeof project.valid !== "boolean"
        || typeof project.detail !== "string"
        || typeof project.is_flutter !== "boolean"
        || typeof project.is_git !== "boolean"
        || !Array.isArray(project.packages)
        || seenPaths.has(project.path)
      ) {
        return false;
      }
      seenPaths.add(project.path);
      return true;
    });
  } catch {
    return [];
  }
}

function requireValidRepository(repository: RepositorySnapshot) {
  if (!repository.valid) throw new Error(repository.detail);
  return repository;
}

function App() {
  const [view, setView] = useState<View>("setup");
  const [setup, setSetup] = useState<SetupStatus | null>(null);
  const [setupLoading, setSetupLoading] = useState(true);
  const [setupError, setSetupError] = useState("");
  const [projects, setProjects] = useState<RepositorySnapshot[]>(loadSavedProjects);
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

  useEffect(() => {
    window.localStorage.setItem(PROJECTS_STORAGE_KEY, JSON.stringify(projects));
  }, [projects]);

  const saveProject = (project: RepositorySnapshot) => {
    setProjects((currentProjects) => [
      project,
      ...currentProjects.filter((savedProject) => savedProject.path !== project.path),
    ]);
    setRepository(project);
  };

  const removeProject = (path: string) => {
    setProjects((currentProjects) =>
      currentProjects.filter((savedProject) => savedProject.path !== path),
    );
    if (repository?.path === path) setRepository(null);
  };

  const refreshAudit = useCallback(async (auditId: string) => {
    const current = await api.getAudit(auditId);
    setActiveAudit(current);
    setAudits((currentAudits) => [
      current,
      ...currentAudits.filter((audit) => audit.id !== current.id),
    ]);
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
    saveProject(audit.repository);
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
              projects={projects}
              audits={audits}
              onValidated={saveProject}
              onRemove={removeProject}
              onNewAudit={() => setView("new-audit")}
              onOpenAudit={openAudit}
            />
          )}
          {view === "new-audit" && (
            <NewAuditView
              repository={repository}
              projects={projects}
              catalogs={setup?.providers ?? []}
              onSelectRepository={saveProject}
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
              audits={audits}
              onRefresh={() => activeAudit ? refreshAudit(activeAudit.id) : Promise.resolve()}
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
      <button className="brand" onClick={() => onNavigate("setup")} aria-label="Perfora home">
        <img className="brand-mark" src="/perfora-mark.svg" alt="" />
        <span>
          <strong>Perfora</strong>
          <small>Performance &amp; security</small>
        </span>
      </button>
      <nav className="primary-nav" aria-label="Primary navigation">
        <p className="nav-label">Workspace</p>
        {items.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={view === id ? "nav-item active" : "nav-item"}
            onClick={() => onNavigate(id)}
            aria-label={label}
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
        aria-label="Settings"
      >
        <Settings size={18} /> Settings
      </button>
      <div className="sidebar-footer">
        <span>v0.3 security depth</span><span className="status-dot" /> localhost
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
  projects,
  audits,
  onValidated,
  onRemove,
  onNewAudit,
  onOpenAudit,
}: {
  repository: RepositorySnapshot | null;
  projects: RepositorySnapshot[];
  audits: AuditRecord[];
  onValidated: (repository: RepositorySnapshot) => void;
  onRemove: (path: string) => void;
  onNewAudit: () => void;
  onOpenAudit: (audit: AuditRecord) => void;
}) {
  const [path, setPath] = useState(repository?.path ?? "");
  const [savedPath, setSavedPath] = useState(repository?.path ?? "");
  const [loadingAction, setLoadingAction] = useState<"browse" | "path" | "saved" | null>(null);
  const [issue, setIssue] = useState<PickerIssue | null>(null);
  const pathValidationVersion = useRef(0);
  const acceptProject = (selectedProject: RepositorySnapshot) => {
    const validRepository = requireValidRepository(selectedProject);
    setPath(validRepository.path);
    setSavedPath(validRepository.path);
    setIssue(null);
    onValidated(validRepository);
  };
  const selectSaved = async (selectedPath: string) => {
    setSavedPath(selectedPath);
    setIssue(null);
    if (!selectedPath) return;
    setLoadingAction("saved");
    try {
      acceptProject(await api.validateRepository(selectedPath));
    } catch (reason) {
      setIssue({
        source: "saved",
        message: reason instanceof Error ? reason.message : "Saved project validation failed",
      });
    } finally {
      setLoadingAction(null);
    }
  };
  const removeSaved = () => {
    if (!savedPath) return;
    onRemove(savedPath);
    if (path === savedPath) setPath("");
    setSavedPath("");
    setIssue(null);
  };
  const validate = async () => {
    const validationVersion = ++pathValidationVersion.current;
    setLoadingAction("path");
    setIssue(null);
    try {
      const selectedProject = await api.validateRepository(path.trim());
      if (validationVersion !== pathValidationVersion.current) return;
      acceptProject(selectedProject);
    } catch (reason) {
      if (validationVersion !== pathValidationVersion.current) return;
      setIssue({
        source: "path",
        message: reason instanceof Error ? reason.message : "Repository validation failed",
      });
    } finally {
      setLoadingAction(null);
    }
  };
  const browse = async () => {
    const validationVersion = ++pathValidationVersion.current;
    setLoadingAction("browse");
    setIssue(null);
    try {
      const selectedProject = await api.pickRepository();
      if (validationVersion !== pathValidationVersion.current) return;
      acceptProject(selectedProject);
    } catch (reason) {
      if (validationVersion !== pathValidationVersion.current) return;
      if (reason instanceof Error && reason.message === "Folder selection was cancelled") {
        return;
      }
      setIssue({
        source: "path",
        message: reason instanceof Error ? reason.message : "Folder selection failed",
      });
    } finally {
      setLoadingAction(null);
    }
  };
  return (
    <section className="page">
      <PageHeading eyebrow="Source context" title="Connect a local Flutter repository." description="Perfora records the exact branch, commit, SDK context, and package fingerprint behind every finding." />
      <div className="repo-connect">
        <div className="connect-icon"><FolderOpen size={28} /></div>
        <div className="connect-copy"><strong>Project picker</strong><span>Choose a saved project or add a local path. Perfora verifies it before use.</span></div>
        <div className="project-picker">
          <div className="picker-field-group">
            <div className="saved-project-control">
              <label>
                Saved projects
                <select
                  value={savedPath}
                  onChange={(event) => void selectSaved(event.target.value)}
                  disabled={projects.length === 0 || loadingAction !== null}
                >
                  <option value="">{projects.length ? "Choose a project" : "No saved projects yet"}</option>
                  {projects.map((project) => (
                    <option key={project.path} value={project.path}>
                      {project.name} — {project.path}
                    </option>
                  ))}
                </select>
              </label>
              <button
                className="button secondary saved-project-action"
                onClick={() => void selectSaved(savedPath)}
                disabled={!savedPath || loadingAction !== null}
                aria-label="Recheck saved project"
                title="Recheck saved project"
              >
                {loadingAction === "saved"
                  ? <LoaderCircle className="spin" size={15} />
                  : <RefreshCw size={15} />}
                Check
              </button>
              <button
                className="button secondary saved-project-action remove-project"
                onClick={removeSaved}
                disabled={!savedPath || loadingAction !== null}
                aria-label="Remove saved project"
              >
                <X size={15} /> Remove
              </button>
            </div>
            {issue?.source === "saved" && (
              <p className="field-error" role="alert" data-source="saved">
                <CircleAlert size={15} /> {issue.message}
              </p>
            )}
            {issue?.source !== "saved" && (
              <p className="picker-hint"><ShieldCheck size={14} /> Saved paths are rechecked before activation.</p>
            )}
          </div>
          <div className="picker-field-group">
            <form
              className="path-input"
              aria-label="Add project by path"
              onSubmit={(event) => {
                event.preventDefault();
                if (path.trim() && loadingAction === null) void validate();
              }}
            >
              <label>
                Project path
                <input
                  value={path}
                  onChange={(event) => {
                    pathValidationVersion.current += 1;
                    setPath(event.target.value);
                    if (issue?.source === "path") setIssue(null);
                  }}
                  placeholder="/Users/you/projects/flutter_app"
                  aria-label="Static project path"
                />
              </label>
              <button
                type="button"
                className="button secondary"
                onClick={browse}
                disabled={loadingAction !== null}
              >
                {loadingAction === "browse" ? <LoaderCircle className="spin" /> : <FolderOpen />}
                Browse…
              </button>
              <button
                type="submit"
                className="button primary"
                disabled={!path.trim() || loadingAction !== null}
              >
                {loadingAction === "path" ? <LoaderCircle className="spin" /> : <Plus />} Add path
              </button>
            </form>
            {issue?.source === "path" && (
              <p className="field-error" role="alert" data-source="path">
                <CircleAlert size={15} /> {issue.message}
              </p>
            )}
            {issue?.source !== "path" && (
              <p className="picker-hint"><FolderOpen size={14} /> Paste an absolute path, quoted path, or file:// URL.</p>
            )}
          </div>
        </div>
      </div>
      {repository && (
        <article className="repository-card">
          <div className="repo-accent" />
          <div className="repo-main">
            <div className="repo-icon"><FileCode2 size={22} /></div>
            <div><p className="eyebrow">Validated Flutter repository</p><h2>{repository.name}</h2><code>{repository.path}</code></div>
          </div>
          <div className="repo-stats">
            <Metric label="Branch" displayValue={repository.branch || "No branch"} icon={GitBranch} />
            <Metric label="Revision" displayValue={repository.commit_sha?.slice(0, 8) || "Uncommitted"} icon={Code2} />
            <Metric label="Packages" displayValue={String(repository.packages.length)} icon={Layers3} />
            <Metric label="Worktree" displayValue={repository.clean ? "Clean" : "Has changes"} icon={repository.clean ? CircleCheck : CircleAlert} />
          </div>
          <div className="repo-actions"><span><ShieldCheck size={16} /> Fingerprint {repository.fingerprint?.slice(0, 12)}</span><button className="button primary" onClick={onNewAudit}><Sparkles size={16} /> New audit</button></div>
        </article>
      )}
      <SectionTitle title="Audit history" subtitle={`${audits.length} immutable run${audits.length === 1 ? "" : "s"}`} />
      <div className="audit-list">
        {audits.length === 0 ? <EmptyState icon={Clock3} title="No audits yet" description="Your first evidence trail will appear here." /> : audits.map((audit) => (
          <button className="audit-row" key={audit.id} onClick={() => onOpenAudit(audit)}>
            <span className={`audit-status ${audit.status}`}><Activity size={16} /></span>
            <span className="audit-row-main"><strong>{audit.repository.name}</strong><small>{auditTypeNames[auditTypeOf(audit)]} · {new Date(audit.created_at).toLocaleString()}</small></span>
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
  projects,
  catalogs,
  onSelectRepository,
  onBack,
  onCreated,
}: {
  repository: RepositorySnapshot | null;
  projects: RepositorySnapshot[];
  catalogs: ProviderCatalog[];
  onSelectRepository: (repository: RepositorySnapshot) => void;
  onBack: () => void;
  onCreated: (audit: AuditRecord) => void;
}) {
  const providerCatalogs = useMemo(
    () => catalogs.filter(
      (catalog) => catalog.available && catalog.models.some((model) => model.compatible),
    ),
    [catalogs],
  );
  const [providerId, setProviderId] = useState<ProviderId | "">("");
  const [auditType, setAuditType] = useState<AuditType>("performance");
  const [modelId, setModelId] = useState("");
  const [modelFilter, setModelFilter] = useState("");
  const providerCatalog = providerCatalogs.find((catalog) => catalog.provider === providerId);
  const providerModels = providerCatalog?.models.filter((model) => model.compatible) ?? [];
  const visibleModels = providerModels.filter((model) =>
    `${model.label} ${model.id}`.toLowerCase().includes(modelFilter.trim().toLowerCase()),
  );
  const selected = providerModels.find((model) => model.id === modelId);
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [repositoryLoading, setRepositoryLoading] = useState(false);
  const [repositoryError, setRepositoryError] = useState("");
  const isRemote = selected ? selected.locality !== "local" : false;
  const selectRepository = async (path: string) => {
    setRepositoryLoading(true);
    setRepositoryError("");
    try {
      onSelectRepository(requireValidRepository(await api.validateRepository(path)));
    } catch (reason) {
      setRepositoryError(
        reason instanceof Error ? reason.message : "Repository validation failed",
      );
    } finally {
      setRepositoryLoading(false);
    }
  };
  const create = async () => {
    if (!repository || !selected) return;
    setLoading(true);
    setError("");
    try {
      const audit = await api.createAudit({
        repository_path: repository.path,
        provider: selected.provider,
        model_id: selected.id,
        audit_type: auditType,
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
          <label className="select-label project-select">
            Project
            <select
              value={repository.path}
              onChange={(event) => void selectRepository(event.target.value)}
              disabled={repositoryLoading}
            >
              {projects.map((project) => (
                <option key={project.path} value={project.path}>
                  {project.name} — {project.path}
                </option>
              ))}
            </select>
          </label>
          {repositoryError && (
            <p className="field-error" role="alert" data-source="audit-project">
              <CircleAlert size={15} /> {repositoryError}
            </p>
          )}
          <div className="selection-card"><FolderGit2 /><div><strong>{repository.name}</strong><code>{repository.path}</code></div><div className="selection-meta"><span>{repository.branch || "no branch"}</span><span>{repository.commit_sha?.slice(0, 8) || "no commit"}</span></div></div>
        </div>
      </div>
      <div className="step-card">
        <span className="step-number">2</span><div className="step-body"><h2>Audit flow</h2><p>Choose the deterministic rule pack to run against this repository.</p>
          <div className="audit-type-picker">
            <button
              type="button"
              className={auditType === "performance" ? "audit-type-option selected" : "audit-type-option"}
              onClick={() => setAuditType("performance")}
            >
              <span className="audit-type-icon"><Activity /></span>
              <span><strong>Lifecycle performance</strong><small>Find owned resources that are not released by Flutter state-management lifecycles.</small></span>
              {auditType === "performance" && <Check size={17} />}
            </button>
            <button
              type="button"
              className={auditType === "security" ? "audit-type-option selected" : "audit-type-option"}
              onClick={() => setAuditType("security")}
            >
              <span className="audit-type-icon security"><LockKeyhole /></span>
              <span><strong>Application security</strong><small>Inspect secrets, transport security, TLS validation, and mobile platform policies.</small></span>
              {auditType === "security" && <Check size={17} />}
            </button>
          </div>
        </div>
      </div>
      <div className="step-card">
        <span className="step-number">3</span><div className="step-body"><h2>Analysis model</h2><p>Select the exact provider and model for this audit.</p>
          <div className="model-provider-picker">
            {providerCatalogs.map((catalog) => (
              <button
                type="button"
                key={catalog.provider}
                className={providerId === catalog.provider ? "model-provider selected" : "model-provider"}
                onClick={() => {
                  setProviderId(catalog.provider);
                  setModelId("");
                  setModelFilter("");
                  setConsent(false);
                }}
              >
                <span className={`provider-logo mini ${catalog.provider}`}><Bot /></span>
                <span><strong>{providerNames[catalog.provider]}</strong><small>{catalog.models.filter((model) => model.compatible).length} models</small></span>
                {providerId === catalog.provider && <Check size={17} />}
              </button>
            ))}
          </div>
          {providerCatalog && (
            <div className="model-choice">
              <label className="select-label">
                Filter models
                <input
                  value={modelFilter}
                  onChange={(event) => setModelFilter(event.target.value)}
                  placeholder={`Search ${providerNames[providerCatalog.provider]} models`}
                />
              </label>
              <label className="select-label">
                Model
                <select value={modelId} onChange={(event) => setModelId(event.target.value)}>
                  <option value="">Select a model</option>
                  {visibleModels.map((model) => (
                    <option key={model.id} value={model.id}>
                      {model.label} · {model.locality}
                    </option>
                  ))}
                </select>
              </label>
              {visibleModels.length === 0 && (
                <p className="field-hint">No models match “{modelFilter}”.</p>
              )}
            </div>
          )}
          {selected && <div className="model-summary"><span className={`provider-logo mini ${selected.provider}`}><Bot /></span><div><strong>{selected.label}</strong><span>{providerNames[selected.provider]} · {selected.locality} · {selected.capability_status}</span></div><Check size={18} /></div>}
          {providerCatalogs.length === 0 && <Notice tone="warning" title="No compatible model found">Configure OpenCode or Ollama, or refresh OpenAI model discovery in Settings.</Notice>}
        </div>
      </div>
      <div className="step-card">
        <span className="step-number">4</span><div className="step-body"><h2>Evidence and privacy</h2><p>{auditType === "security" ? "The security rule pack reports only directly observed source and platform configuration evidence." : "The lifecycle rule pack covers Riverpod, Provider, Bloc/Cubit, and GetX."}</p>
          <div className="rule-strip"><ShieldCheck /><div><strong>{auditType === "security" ? "Deterministic security analysis" : "Deterministic lifecycle analysis"}</strong><span>{auditType === "security" ? "Checks hardcoded credentials, cleartext transport, TLS bypasses, Android manifests, and iOS transport policy." : "Owned controllers, streams, timers, and workers are matched to cleanup hooks."}</span></div><span className="rule-count">{auditType === "security" ? "5 rules" : "4 frameworks"}</span></div>
          {isRemote && <label className="consent-card"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /><span><strong>I approve evidence snippets for this remote provider</strong><small>Perfora redacts likely secrets and records the transmitted file manifest.</small></span></label>}
        </div>
      </div>
      {error && <Notice tone="danger" title="Audit could not start">{error}</Notice>}
      <div className="create-footer"><button className="button ghost" onClick={onBack}>Back</button><div><span>No silent model fallback</span><button className="button primary large" onClick={create} disabled={!selected || loading || (isRemote && !consent)}>{loading ? <LoaderCircle className="spin" /> : <Play />} Start audit</button></div></div>
    </section>
  );
}

const triageOptions: TriageStatus[] = [
  "new",
  "investigating",
  "in_progress",
  "resolved",
  "false_positive",
  "risk_accepted",
  "reopened",
];

function readableStatus(value: string) {
  return value.replaceAll("_", " ");
}

function comparisonStatus(finding: Finding, comparison: AuditComparison | null) {
  if (comparison?.regressed_finding_ids?.includes(finding.id)) return "regressed";
  if (comparison?.severity_changes?.some((change) => change.finding_id === finding.id)) return "severity_changed";
  if (comparison?.new_finding_ids?.includes(finding.id)) return "new";
  if (comparison?.unchanged_finding_ids?.includes(finding.id)) return "unchanged";
  return finding.comparison_status;
}

function AuditWorkspace({
  audit,
  audits,
  onRefresh,
  onNewAudit,
}: {
  audit: AuditRecord | null;
  audits: AuditRecord[];
  onRefresh: () => Promise<void>;
  onNewAudit: () => void;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(audit?.findings[0]?.id ?? null);
  const [baselineId, setBaselineId] = useState(audit?.baseline_audit_id ?? "");
  const [comparison, setComparison] = useState<AuditComparison | null>(null);
  const [comparisonError, setComparisonError] = useState("");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [triageFilter, setTriageFilter] = useState("all");
  const [comparisonFilter, setComparisonFilter] = useState("all");

  useEffect(() => {
    setBaselineId(audit?.baseline_audit_id ?? "");
    setComparison(null);
  }, [audit?.id, audit?.baseline_audit_id]);

  useEffect(() => {
    if (!audit || !["completed", "partial"].includes(audit.status)) return;
    let active = true;
    setComparisonError("");
    void api.compareAudit(audit.id, baselineId || undefined)
      .then((result) => active && setComparison(result))
      .catch((reason) => active && setComparisonError(reason instanceof Error ? reason.message : "Comparison failed"));
    return () => { active = false; };
  }, [audit?.id, audit?.status, baselineId]);

  const eligibleBaselines = useMemo(() => {
    if (!audit) return [];
    return audits.filter((candidate) =>
      candidate.id !== audit.id
      && candidate.repository.path === audit.repository.path
      && auditTypeOf(candidate) === auditTypeOf(audit)
      && new Date(candidate.created_at) < new Date(audit.created_at)
      && ["completed", "partial"].includes(candidate.status));
  }, [audit, audits]);

  const filteredFindings = useMemo(() => {
    if (!audit) return [];
    const query = search.trim().toLowerCase();
    return audit.findings.filter((finding) => {
      const delta = comparisonStatus(finding, comparison);
      return (!query || `${finding.title} ${finding.file} ${finding.rule_id} ${finding.owner ?? ""}`.toLowerCase().includes(query))
        && (severityFilter === "all" || finding.severity === severityFilter)
        && (triageFilter === "all" || (finding.triage_status ?? "new") === triageFilter)
        && (comparisonFilter === "all" || delta === comparisonFilter);
    });
  }, [audit, comparison, comparisonFilter, search, severityFilter, triageFilter]);

  useEffect(() => {
    if (filteredFindings.length && !filteredFindings.some((finding) => finding.id === selectedId)) {
      setSelectedId(filteredFindings[0].id);
    }
  }, [filteredFindings, selectedId]);

  if (!audit) return <section className="page"><EmptyState icon={SearchCode} title="No audit selected" description="Start or open an audit to inspect its evidence." action={<button className="button primary" onClick={onNewAudit}>Create audit</button>} /></section>;
  const auditType = auditTypeOf(audit);
  const selected = filteredFindings.find((finding) => finding.id === selectedId) ?? filteredFindings[0];
  const progress = audit.events.at(-1)?.progress ?? 0;
  const skippedCoverage = Object.entries(audit.scan_coverage?.skipped_by_reason ?? {}).map(([reason, count]) => `${reason.replaceAll("_", " ")}: ${count}`).join(", ");
  const scannedCoverage = Object.entries(audit.scan_coverage?.scanned_by_type ?? {}).map(([type, count]) => `${type.replaceAll("_", " ")}: ${count}`).join(", ");
  const platformCoverage = Object.entries(audit.scan_coverage?.coverage_by_platform ?? {}).map(([platform, count]) => `${platform}: ${count}`).join(", ");
  const controlCoverage = Object.entries(audit.scan_coverage?.rules_by_control_group ?? {}).map(([group, rules]) => `${group}: ${rules.length}`).join(", ");
  const dependencyCoverage = Object.entries(audit.dependency_inventory?.coverage_by_ecosystem ?? {}).map(([ecosystem, count]) => `${ecosystem}: ${count}`).join(", ");
  const privacyCoverage = Object.entries(audit.dependency_inventory?.privacy_sdk_counts ?? {}).map(([category, count]) => `${category.replaceAll("_", " ")}: ${count}`).join(", ");
  return (
    <section className="workspace-page">
      <div className="workspace-header">
        <div><p className="eyebrow">{audit.repository.name} · {audit.repository.branch || "detached"}</p><h1>{auditType === "security" ? "Security evidence audit" : "Lifecycle performance audit"}</h1><div className="audit-meta"><span><Bot size={14} /> {providerNames[audit.provider]}/{audit.model_id}</span><span><GitBranch size={14} /> {audit.repository.commit_sha?.slice(0, 8) || "no commit"}</span><span><Code2 size={14} /> {audit.rule_pack ? `${audit.rule_pack.id}@${audit.rule_pack.version}` : "legacy rule pack"}</span><span><Clock3 size={14} /> {new Date(audit.created_at).toLocaleTimeString()}</span></div></div>
        <div className="workspace-actions"><button className="button secondary" onClick={() => void onRefresh()}><RefreshCw size={16} /> Refresh</button><ExportMenu audit={audit} /></div>
      </div>
      <div className="progress-band"><div className="progress-copy"><span className={`pulse ${audit.status}`} /> <strong>{audit.events.at(-1)?.message || audit.status}</strong><span>{progress}%</span></div><div className="progress-track"><span style={{ width: `${progress}%` }} /></div></div>
      <div className="evidence-summary">
        <Metric label="Confirmed findings" displayValue={String(audit.findings.filter((finding) => finding.status === "confirmed").length)} icon={ShieldCheck} />
        <Metric label="High severity" displayValue={String(audit.findings.filter((finding) => ["high", "critical"].includes(finding.severity)).length)} icon={Zap} />
        <Metric label="Files scanned" displayValue={String(audit.scan_coverage?.files_scanned ?? 0)} icon={FileCode2} />
        <Metric label="Run status" displayValue={audit.status} icon={Activity} />
      </div>
      {audit.error && <Notice tone={audit.status === "partial" ? "warning" : "danger"} title={audit.status === "partial" ? "Partial audit" : "Audit failed"}>{audit.error}</Notice>}
      {audit.scan_coverage && <div className="context-manifest coverage-manifest"><SearchCode size={16} /><span><strong>Scan coverage:</strong> discovered {audit.scan_coverage.files_discovered}, scanned {audit.scan_coverage.files_scanned}, skipped {audit.scan_coverage.files_skipped}. Scanned types: {scannedCoverage || "none"}. Skip reasons: {skippedCoverage || "none"}. Rules executed: {audit.scan_coverage.rules_executed.length}. Analyzer {audit.analyzer_version ?? "unknown"}.</span></div>}
      {auditType === "security" && <div className="security-depth-summary"><div><p className="eyebrow">Standards coverage</p><strong>{platformCoverage || "No platform files scanned"}</strong><span>{controlCoverage || "No mapped control groups executed"}</span></div><div><p className="eyebrow">Dependency inventory</p><strong>{audit.dependency_inventory?.components.length ?? 0} components · {audit.dependency_inventory?.manifests.length ?? 0} manifests</strong><span>{dependencyCoverage || "No supported dependency manifests"}{privacyCoverage ? ` · Privacy-sensitive SDKs: ${privacyCoverage}` : ""}</span></div><div><p className="eyebrow">Vulnerability matching</p><strong>Not requested</strong><span>Local inventory only; no dependency data was sent to an online service.</span></div></div>}
      {["completed", "partial"].includes(audit.status) && (
        <div className="comparison-band">
          <div className="comparison-heading"><div><p className="eyebrow">Baseline comparison</p><strong>{comparison?.baseline_audit_id ? `Against ${comparison.baseline_audit_id.slice(0, 8)}` : "First observed audit"}</strong></div><label>Baseline<select aria-label="Comparison baseline" value={baselineId} onChange={(event) => setBaselineId(event.target.value)}><option value="">Automatic previous audit</option>{eligibleBaselines.map((candidate) => <option key={candidate.id} value={candidate.id}>{new Date(candidate.created_at).toLocaleString()} · {candidate.id.slice(0, 8)}</option>)}</select></label></div>
          <div className="comparison-metrics"><span><strong>{comparison?.new_finding_ids?.length ?? 0}</strong> New</span><span><strong>{comparison?.unchanged_finding_ids?.length ?? 0}</strong> Unchanged</span><span><strong>{comparison?.resolved_findings?.length ?? 0}</strong> Resolved</span><span className="danger"><strong>{comparison?.regressed_finding_ids?.length ?? 0}</strong> Regressed</span><span><strong>{comparison?.severity_changes?.length ?? 0}</strong> Severity changed</span></div>
          {comparison?.dependency_changes && <div className="dependency-change-band"><strong>Dependency changes</strong><span>+{comparison.dependency_changes.added.length} added</span><span>~{comparison.dependency_changes.updated.length} updated</span><span>−{comparison.dependency_changes.removed.length} removed</span></div>}
          {comparisonError && <p className="comparison-error">{comparisonError}</p>}
        </div>
      )}
      <div className="findings-filters">
        <label>Search<input aria-label="Search findings" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Title, file, rule, or owner" /></label>
        <label>Severity<select aria-label="Filter severity" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="all">All severities</option>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
        <label>Triage<select aria-label="Filter triage" value={triageFilter} onChange={(event) => setTriageFilter(event.target.value)}><option value="all">All triage states</option>{[...triageOptions, "verified_resolved" as TriageStatus].map((value) => <option key={value} value={value}>{readableStatus(value)}</option>)}</select></label>
        <label>Change<select aria-label="Filter comparison" value={comparisonFilter} onChange={(event) => setComparisonFilter(event.target.value)}><option value="all">All changes</option>{["new", "unchanged", "regressed", "severity_changed"].map((value) => <option key={value} value={value}>{readableStatus(value)}</option>)}</select></label>
      </div>
      <div className="investigation-grid">
        <aside className="findings-panel">
          <div className="panel-heading"><div><p className="eyebrow">Evidence queue</p><h2>Findings</h2></div><span>{filteredFindings.length}</span></div>
          {audit.findings.length === 0 ? <div className="panel-empty"><LoaderCircle className={audit.status === "running" ? "spin" : ""} /><strong>{audit.status === "running" ? `Analyzing ${auditType} evidence` : `No ${auditType} findings`}</strong></div> : filteredFindings.length === 0 ? <div className="panel-empty"><SearchCode /><strong>No findings match these filters</strong></div> : filteredFindings.map((finding) => { const delta = comparisonStatus(finding, comparison); return <button key={finding.id} className={selected?.id === finding.id ? "finding-row selected" : "finding-row"} onClick={() => setSelectedId(finding.id)}><span className={`severity-mark ${finding.severity}`} /><div><span className="finding-framework">{finding.framework}</span><strong>{finding.title}</strong><small>{finding.file}:{finding.line}</small><span className="row-statuses"><em>{readableStatus(finding.triage_status ?? "new")}</em>{delta && <em className={delta}>{readableStatus(delta)}</em>}</span></div><span className="confidence">{Math.round(finding.confidence * 100)}%</span></button>; })}
        </aside>
        <div className="detail-panel">
          {selected ? <FindingDetail finding={selected} audit={audit} onRefresh={onRefresh} /> : <EmptyState icon={SearchCode} title="No finding selected" description={audit.findings.length ? "Adjust the filters to continue triage." : auditType === "security" ? "The deterministic analyzer is inspecting application security controls." : "The deterministic analyzer is inspecting lifecycle ownership."} />}
        </div>
      </div>
    </section>
  );
}

function dateInputValue(value?: string) {
  return value ? value.slice(0, 10) : "";
}

function FindingDetail({ finding, audit, onRefresh }: { finding: Finding; audit: AuditRecord; onRefresh: () => Promise<void> }) {
  const [promptLoading, setPromptLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState(false);
  const [triageStatus, setTriageStatus] = useState<TriageStatus>(finding.triage_status ?? "new");
  const [owner, setOwner] = useState(finding.owner ?? "");
  const [dueAt, setDueAt] = useState(dateInputValue(finding.due_at));
  const [resolutionCommit, setResolutionCommit] = useState(finding.resolution_commit ?? "");
  const [dispositionReason, setDispositionReason] = useState(finding.disposition_reason ?? "");
  const [suppressionExpiresAt, setSuppressionExpiresAt] = useState(dateInputValue(finding.suppression_expires_at));
  const [ticketUrl, setTicketUrl] = useState(finding.ticket_url ?? "");
  const [note, setNote] = useState("");
  useEffect(() => {
    setCopied(false); setSaved(false); setError(""); setNote("");
    setTriageStatus(finding.triage_status ?? "new"); setOwner(finding.owner ?? "");
    setDueAt(dateInputValue(finding.due_at)); setResolutionCommit(finding.resolution_commit ?? "");
    setDispositionReason(finding.disposition_reason ?? "");
    setSuppressionExpiresAt(dateInputValue(finding.suppression_expires_at));
    setTicketUrl(finding.ticket_url ?? "");
  }, [finding]);
  const copyPrompt = async () => {
    setPromptLoading(true); setError("");
    try {
      const result = await api.buildAgentPrompt(audit.id, finding.id);
      await writeClipboard(result.prompt);
      setCopied(true);
    } catch (reason) {
      setCopied(false);
      setError(reason instanceof Error ? reason.message : "Prompt copy failed");
    } finally {
      setPromptLoading(false);
    }
  };
  const saveTriage = async () => {
    setSaving(true); setSaved(false); setError("");
    try {
      const update: FindingUpdate = {
        owner: owner || null,
        due_at: dueAt ? new Date(`${dueAt}T23:59:59Z`).toISOString() : null,
        resolution_commit: resolutionCommit || null,
        disposition_reason: dispositionReason || null,
        suppression_expires_at: suppressionExpiresAt ? new Date(`${suppressionExpiresAt}T23:59:59Z`).toISOString() : null,
        ticket_url: ticketUrl || null,
        note: note || undefined,
      };
      if (triageStatus !== "verified_resolved") update.triage_status = triageStatus;
      await api.updateFinding(audit.id, finding.id, update);
      setSaved(true);
      await onRefresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Finding update failed");
    } finally {
      setSaving(false);
    }
  };
  const verifyResolution = async () => {
    setVerificationLoading(true); setError("");
    try {
      await api.verifyFinding(audit.id, finding.id);
      await onRefresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Verification failed");
    } finally {
      setVerificationLoading(false);
    }
  };
  const verificationAttempts = finding.verification_attempts ?? [];
  const latestVerification = verificationAttempts.at(-1);
  const canVerify = Boolean(finding.fingerprint)
    && ["resolved", "verified_resolved"].includes(finding.triage_status ?? "new");
  return (
    <>
      <div className="detail-heading"><div><div className="finding-tags"><span className={`severity-pill ${finding.severity}`}>{finding.severity}</span><span className="confirmed-pill"><ShieldCheck size={13} /> {finding.status}</span><span>{finding.framework}</span><span className={`triage-pill ${finding.triage_status ?? "new"}`}>{readableStatus(finding.triage_status ?? "new")}</span></div><h2>{finding.title}</h2><code>{finding.file}:{finding.line} · {finding.symbol}</code></div><button className="button primary" onClick={copyPrompt} disabled={promptLoading}>{promptLoading ? <LoaderCircle className="spin" /> : copied ? <Check /> : <Copy />} {copied ? "Copied" : "Copy prompt"}</button></div>
      <div className="triage-panel">
        <div className="triage-heading"><div><p className="eyebrow">Finding lifecycle</p><h3>Assign, decide, and document</h3></div><button className="button secondary" onClick={() => void saveTriage()} disabled={saving}>{saving ? <LoaderCircle className="spin" /> : saved ? <Check /> : <ShieldCheck />} {saved ? "Saved" : "Save triage"}</button></div>
        <div className="triage-grid">
          <label>Status<select aria-label="Triage status" value={triageStatus} onChange={(event) => setTriageStatus(event.target.value as TriageStatus)}>{finding.triage_status === "verified_resolved" && <option value="verified_resolved">verified resolved</option>}{triageOptions.map((value) => <option key={value} value={value}>{readableStatus(value)}</option>)}</select><small>Verified resolved is assigned only by a deterministic re-scan.</small></label>
          <label>Owner<input aria-label="Finding owner" value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Team or person" /></label>
          <label>Due date<input aria-label="Finding due date" type="date" value={dueAt} onChange={(event) => setDueAt(event.target.value)} /></label>
          <label>External ticket<input aria-label="External ticket" value={ticketUrl} onChange={(event) => setTicketUrl(event.target.value)} placeholder="Ticket URL or ID" /></label>
          <label>Resolution commit<input aria-label="Resolution commit" value={resolutionCommit} onChange={(event) => setResolutionCommit(event.target.value)} placeholder="Commit SHA or reference" /></label>
          <label>Suppression expires<input aria-label="Suppression expiration" type="date" value={suppressionExpiresAt} onChange={(event) => setSuppressionExpiresAt(event.target.value)} /></label>
          <label className="wide">Disposition reason<textarea aria-label="Disposition reason" value={dispositionReason} onChange={(event) => setDispositionReason(event.target.value)} placeholder="Required for false positive and risk accepted" /></label>
          <label className="wide">Add note<textarea aria-label="Finding note" value={note} onChange={(event) => setNote(event.target.value)} placeholder="Append context without replacing prior notes" /></label>
        </div>
        {(finding.notes?.length > 0 || finding.status_history?.length > 0) && <div className="triage-history"><p className="eyebrow">History</p>{finding.status_history?.map((change) => <div key={`${change.changed_at}-${change.to_status}`}><Clock3 size={14} /><span><strong>{readableStatus(change.from_status)} → {readableStatus(change.to_status)}</strong><small>{new Date(change.changed_at).toLocaleString()}{change.reason ? ` · ${change.reason}` : ""}</small></span></div>)}{finding.notes?.map((entry) => <div key={entry.id}><Code2 size={14} /><span><strong>Note</strong><small>{entry.body} · {new Date(entry.created_at).toLocaleString()}</small></span></div>)}</div>}
      </div>
      <div className="verification-panel">
        <div className="verification-heading"><div><p className="eyebrow">Deterministic verification</p><h3>Prove the finding no longer reproduces</h3></div><button className="button secondary" onClick={() => void verifyResolution()} disabled={!canVerify || verificationLoading}>{verificationLoading ? <LoaderCircle className="spin" /> : <RefreshCw />} Verify resolution</button></div>
        <p className="verification-guidance">Verification runs the same audit rule pack against the current repository. A result is certified only when the rule executes and the finding source is scanned or has been removed.</p>
        {!finding.fingerprint && <div className="verification-blocked"><CircleAlert size={16} /><span>Legacy finding: run a new audit to create a stable fingerprint before verification.</span></div>}
        {finding.fingerprint && !canVerify && <div className="verification-blocked"><CircleAlert size={16} /><span>Mark this finding resolved before running verification.</span></div>}
        {latestVerification && <div className={`verification-result ${latestVerification.outcome}`}><div><span className="verification-outcome">{readableStatus(latestVerification.outcome)}</span><strong>{latestVerification.message}</strong><small>{new Date(latestVerification.completed_at).toLocaleString()} · analyzer {latestVerification.analyzer_version} · {latestVerification.rule_pack.id}@{latestVerification.rule_pack.version}</small></div><div className="verification-checks"><span className={latestVerification.rule_executed ? "passed" : "failed"}>{latestVerification.rule_executed ? <Check /> : <X />} Rule executed</span><span className={latestVerification.file_scanned || !latestVerification.source_present ? "passed" : "failed"}>{latestVerification.file_scanned || !latestVerification.source_present ? <Check /> : <X />} {latestVerification.source_present ? "Source scanned" : "Source removed"}</span></div>{latestVerification.observed_evidence.length > 0 && <div className="verification-observed"><strong>Current evidence</strong>{latestVerification.observed_evidence.map((item) => <span key={item}>{item}</span>)}</div>}</div>}
        {verificationAttempts.length > 1 && <details className="verification-history"><summary>{verificationAttempts.length} verification attempts</summary>{verificationAttempts.slice().reverse().map((attempt) => <div key={attempt.id}><span className={`verification-dot ${attempt.outcome}`} /><strong>{readableStatus(attempt.outcome)}</strong><small>{new Date(attempt.completed_at).toLocaleString()} · {attempt.message}</small></div>)}</details>}
      </div>
      <div className="detail-section"><p className="eyebrow">Deterministic explanation</p><p className="lead-copy">{finding.explanation}</p></div>
      <div className="detail-section"><p className="eyebrow">Deterministic evidence</p><div className="evidence-list">{finding.evidence.map((evidenceLine) => <div key={evidenceLine}><CircleCheck size={16} /><span>{evidenceLine}</span></div>)}</div></div>
      <div className="detail-section recommendation"><div className="recommendation-icon"><ShieldCheck size={19} /></div><div><p className="eyebrow">Deterministic recommendation</p><p>{finding.recommendation}</p></div></div>
      {finding.control_group && <div className="detail-section standards-section"><p className="eyebrow">Standards mapping · {finding.control_group}</p><div className="standard-links">{finding.standards?.map((standard) => <a key={standard.id} href={standard.url} target="_blank" rel="noreferrer"><strong>{standard.id}</strong><span>{standard.title}</span></a>)}</div><div className="standards-guidance"><div><strong>Detection limitations</strong><ul>{finding.detection_limitations?.map((item) => <li key={item}>{item}</li>)}</ul></div><div><strong>Manual verification</strong><ul>{finding.manual_verification?.map((item) => <li key={item}>{item}</li>)}</ul></div></div>{finding.false_positive_guidance && <p><strong>False-positive guidance:</strong> {finding.false_positive_guidance}</p>}</div>}
      {finding.model_enrichment && <div className="detail-section recommendation"><div className="recommendation-icon"><Sparkles size={19} /></div><div><p className="eyebrow">Model perspective · {finding.model_enrichment.provider ?? audit.provider}/{finding.model_enrichment.model_id ?? audit.model_id}</p><p>{finding.model_enrichment.explanation}{finding.model_enrichment.recommendation ? ` ${finding.model_enrichment.recommendation}` : ""}</p></div></div>}
      <div className="context-manifest"><Code2 size={16} /><span><strong>Finding identity:</strong> {finding.rule_id}@{finding.rule_version || "legacy"} · {finding.fingerprint || "legacy record without fingerprint"}</span></div>
      <div className="context-manifest"><LockKeyhole size={16} /><span><strong>Context manifest:</strong> only {audit.context_manifest.length ? audit.context_manifest.join(", ") : "deterministic evidence"} was selected for model enrichment.</span></div>
      <div className="context-manifest"><Copy size={16} /><span><strong>Agent handoff:</strong> Copy prompt assembles the audit provenance, all finding evidence and recommendations, repository state, and the complete secret-redacted source file. It does not contact a model or modify the repository.</span></div>
      {error && <Notice tone="danger" title="Finding action">{error}</Notice>}
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
          <SectionTitle title="Evidence policy" subtitle="Trust boundaries are explicit" />
          {["Deterministic evidence remains authoritative", "Model enrichment is labeled separately", "Agent handoff never modifies the repository"].map((policy) => <div className="command-row" key={policy}><ShieldCheck size={16} /><span>{policy}</span><span><Check size={14} /> enforced</span></div>)}
        </div>
        <aside className="privacy-panel">
          <div className="privacy-illustration"><ShieldCheck size={38} /><span className="orbit one" /><span className="orbit two" /></div>
          <p className="eyebrow">Privacy posture</p><h2>Zero automatic telemetry.</h2><p>Repository contents, prompts, responses, and audit logs remain local except for evidence explicitly approved for a remote model.</p>
          <ul><li><Check /> Secrets redacted before model context</li><li><Check /> Unknown routing treated as remote</li><li><Check /> Context manifest saved per audit</li><li><Check /> No silent provider fallback</li></ul>
          <div className="key-status"><KeyRound size={17} /><div><strong>OpenAI credential</strong><span>{setup?.providers.find((provider) => provider.provider === "openai")?.available ? "Configured in local environment" : "Not configured"}</span></div></div>
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

function Metric({ label, displayValue, icon: Icon }: { label: string; displayValue: string; icon: typeof Activity }) {
  return <div className="metric"><span className="metric-icon"><Icon size={17} /></span><div><small>{label}</small><strong>{displayValue}</strong></div></div>;
}

function Notice({ tone, title, children }: { tone: "warning" | "danger"; title: string; children: React.ReactNode }) {
  return <div className={`notice ${tone}`}><CircleAlert size={19} /><div><strong>{title}</strong><span>{children}</span></div></div>;
}

function EmptyState({ icon: Icon, title, description, action }: { icon: typeof Activity; title: string; description: string; action?: React.ReactNode }) {
  return <div className="empty-state"><span><Icon size={24} /></span><h2>{title}</h2><p>{description}</p>{action}</div>;
}

function ExportMenu({ audit }: { audit: AuditRecord }) {
  return <div className="export-group"><Download size={16} />{(["html", "json", "sarif", "cyclonedx"] as const).map((format) => <a key={format} href={`/api/audits/${audit.id}/export?format=${format}`} download>{format === "cyclonedx" ? "SBOM" : format.toUpperCase()}</a>)}</div>;
}

async function writeClipboard(value: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textArea = document.createElement("textarea");
  textArea.value = value;
  textArea.setAttribute("readonly", "");
  textArea.style.position = "fixed";
  textArea.style.opacity = "0";
  document.body.append(textArea);
  textArea.select();
  const copied = document.execCommand("copy");
  textArea.remove();
  if (!copied) throw new Error("Clipboard access is unavailable in this browser");
}

export default App;
