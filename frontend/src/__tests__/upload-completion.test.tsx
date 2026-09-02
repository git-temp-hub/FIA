/**
 * Reproduction: upload reaches 100% and the next-step UI must appear.
 *
 * Covers both the stay-on-page case and the navigate-away-and-back case,
 * because a long upload (a 66 GB dump takes many minutes) makes navigating
 * away during the transfer the normal thing to do.
 */

import { describe, expect, test, vi, beforeEach } from "vitest";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, Link } from "react-router-dom";

import UploadProvider from "../upload/UploadProvider";
import UploadPage from "../pages/Upload/UploadPage";
import { ToastProvider } from "../components/ui/ToastProvider";

const uploadState = {
  resolve: null as ((value: unknown) => void) | null,
  onProgress: null as ((p: number) => void) | null,
};

vi.mock("../services/uploadService", () => ({
  uploadMemoryDump: vi.fn(
    (_file: File, onProgress?: (p: number) => void) =>
      new Promise((resolve) => {
        uploadState.onProgress = onProgress ?? null;
        uploadState.resolve = resolve;
      }),
  ),
}));

const serverInvestigations = { items: [] as unknown[] };

vi.mock("../services/investigationService", () => ({
  getInvestigationStatus: vi.fn(() => Promise.resolve({})),
  startInvestigation: vi.fn(() => Promise.resolve({})),
  listInvestigations: vi.fn(() => Promise.resolve(serverInvestigations.items)),
}));

function OtherPage() {
  return <div>Dashboard placeholder</div>;
}

function InvestigationStub() {
  return <div>investigation-detail-page</div>;
}

function TestApp() {
  return (
    <ToastProvider>
      <UploadProvider>
        <MemoryRouter initialEntries={["/upload"]}>
          <nav>
            <Link to="/upload">nav-upload</Link>
            <Link to="/dashboard">nav-dashboard</Link>
          </nav>
          <Routes>
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/dashboard" element={<OtherPage />} />
            <Route
              path="/investigation/:investigationId"
              element={<InvestigationStub />}
            />
          </Routes>
        </MemoryRouter>
      </UploadProvider>
    </ToastProvider>
  );
}

const SERVER_RESPONSE = {
  status: "success",
  investigation_id: "INV-REAL-1",
  filename: "host-dump.raw",
  size: 71_000_000_000,
  sha256: "a4dd17f3127aabeb",
  stored_path: "C:/storage/uploads/host-dump.raw",
};

async function startUpload(user: ReturnType<typeof userEvent.setup>) {
  const file = new File(["x".repeat(32)], "host-dump.raw");
  const input = document.querySelector(
    'input[type="file"]',
  ) as HTMLInputElement;

  await user.upload(input, file);
  await user.click(await screen.findByRole("button", { name: /upload/i }));
}

beforeEach(() => {
  uploadState.resolve = null;
  uploadState.onProgress = null;
  serverInvestigations.items = [];
});

describe("upload completion", () => {
  test("stayed on page: next step appears after 100%", async () => {
    const user = userEvent.setup();
    render(<TestApp />);

    await startUpload(user);

    // All bytes transferred; server has not responded yet.
    await act(async () => {
      uploadState.onProgress?.(100);
    });

    expect(await screen.findByText("100%")).toBeTruthy();

    // Server finishes writing/hashing and responds.
    await act(async () => {
      uploadState.resolve?.(SERVER_RESPONSE);
    });

    // Auto-navigation to the investigation page is the next step here.
    expect(
      await screen.findByText("investigation-detail-page"),
    ).toBeTruthy();
  });

  test("navigated away during upload: next step still reachable", async () => {
    const user = userEvent.setup();
    render(<TestApp />);

    await startUpload(user);

    await act(async () => {
      uploadState.onProgress?.(100);
    });

    // User leaves the page while the server is still processing.
    await user.click(screen.getByText("nav-dashboard"));
    expect(screen.getByText("Dashboard placeholder")).toBeTruthy();

    await act(async () => {
      uploadState.resolve?.(SERVER_RESPONSE);
    });

    // Back on the upload page, the completed upload must offer the next
    // action rather than sitting on a stale progress bar or a blank form.
    await user.click(screen.getByText("nav-upload"));

    expect(
      await screen.findByText(/go to investigation/i),
    ).toBeTruthy();
    expect(screen.getByText("INV-REAL-1")).toBeTruthy();
  });
});

describe("recovery when client upload state is lost", () => {
  test("a dump uploaded server-side still offers Start Investigation", async () => {
    // Simulates the real incident: the transfer completed and the server
    // stored the dump, but the browser's in-memory upload state was gone
    // (reload / hot-reload / crash), so there is no client-side record of it.
    serverInvestigations.items = [
      {
        investigation_id: "INV-20260902-C3D2F9",
        filename: "host-dump.raw",
        status: "uploaded",
        progress: 0,
        uploaded_at: "2026-09-02T07:56:31",
        evidence_count: 0,
        plugin_count: 0,
      },
    ];

    render(<TestApp />);

    // The next action must still be offered, sourced from the backend.
    expect(
      await screen.findByText(/uploaded, awaiting analysis/i),
    ).toBeTruthy();
    expect(screen.getByText("host-dump.raw")).toBeTruthy();
    expect(
      screen.getByRole("link", { name: /start investigation/i }),
    ).toBeTruthy();
  });
});
