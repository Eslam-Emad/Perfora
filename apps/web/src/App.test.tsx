import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

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
