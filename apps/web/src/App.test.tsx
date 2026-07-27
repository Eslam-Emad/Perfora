import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";

vi.stubGlobal(
  "fetch",
  vi.fn(() =>
    Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ tools: [], providers: [], audits: [] }),
    }),
  ),
);

describe("Perfora shell", () => {
  it("renders the local-first product identity", async () => {
    render(<App />);
    expect(await screen.findByText("0/3 providers ready")).toBeInTheDocument();
    expect(screen.getAllByText("Perfora")).toHaveLength(2);
    expect(screen.getByText("Make the invisible setup visible.")).toBeInTheDocument();
    expect(screen.getByText("localhost only")).toBeInTheDocument();
  });
});
