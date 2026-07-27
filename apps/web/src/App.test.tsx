import { fireEvent, render, screen } from "@testing-library/react";
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
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve(body),
  });
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
});
