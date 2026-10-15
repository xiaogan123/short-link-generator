import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import App from "./App";
import type { Plan } from "./types";

const c = vi.hoisted(() => ({ resolve: null as ((value: Plan) => void) | null, requests: 0 }));
vi.mock("./bridge", () => ({ preview: true, errorMessage: String, dispatch: async (action: string) => {
  if (action === "get_state") return { accounts: [], domains: [{ id: "d", accountId: "a", zoneId: "z", host: "go.example.com", prefix: "r", routeId: "r" }], links: ["one", "two"].map(slug => ({ domainId: "d", slug, cnUrl: "https://example.com/zh", defaultUrl: "https://example.com/en", updated: "" })), pools: [], pendingOperations: [], pendingActions: [] };
  if (action === "prepare_change") { c.requests++; return new Promise<Plan>(resolve => { c.resolve = resolve; }); }
  throw Error(action);
} }));
afterEach(() => { cleanup(); c.resolve = null; c.requests = 0; });
it("prepares only one destructive target while its confirmation is loading", async () => {
  await act(async () => { render(<App />); });
  fireEvent.click(screen.getByRole("button", { name: "详情 one" }));
  fireEvent.click(screen.getByRole("button", { name: "删除 one" }));
  fireEvent.click(screen.getByRole("button", { name: "详情 two" }));
  const second = screen.getByRole("button", { name: "删除 two" }) as HTMLButtonElement;
  expect(second.disabled).toBe(true);
  fireEvent.click(second);
  expect(c.requests).toBe(1);
  await act(async () => { c.resolve?.({ id: "one", title: "删除 one", steps: ["删除 one"], warnings: [], expiresAt: new Date(Date.now() + 300000).toISOString() }); });
  expect(screen.getByRole("dialog", { name: "删除 one" }).textContent).toContain("go.example.com/r/one");
  expect(screen.queryByRole("dialog", { name: "删除 two" })).toBeNull();
});
