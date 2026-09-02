/**
 * Regression tests for state continuity across in-app navigation.
 *
 * These reproduce the two reported bugs directly:
 *
 *   (a) Start an upload, navigate away via the nav while bytes are still
 *       transferring, navigate back — the transfer and its percentage must
 *       still be shown, not a blank form.
 *
 *   (b) Start an analysis, navigate away, navigate back to the detail page
 *       — the running investigation and its true backend progress must be
 *       shown, not a reset/blank view.
 *
 * Both navigate through the router the way the sidebar does (route change,
 * component unmount/remount) rather than reloading the page, which is what
 * distinguishes these from the already-working refresh case.
 */

import { afterEach, describe, expect, test, vi, beforeEach } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, Link } from "react-router-dom";

import UploadProvider from "../upload/UploadProvider";
import UploadPage from "../pages/Upload/UploadPage";
import InvestigationPage from "../pages/Investigation/InvestigationPage";
import { ToastProvider } from "../components/ui/ToastProvider";

// ---------------------------------------------------------------------------
// Service mocks: the tests exercise component/state behaviour, so the network
// layer is replaced with controllable fakes.
// ---------------------------------------------------------------------------

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

const statusState = {
  payload: {
    investigation_id: "INV-TEST-1",
    status: "running",
    progress: 40,
    phase: "volatility",
    current_plugin: "windows.netscan",
    total_plugins: 10,
    finished_plugins: 4,
    completed_plugins: 3,
    failed_plugins: 1,
    estimated_seconds_remaining: 90,
    last_error: null,
    filename: "real-dump.raw",
    sha256: "abc123def456",
    file_size: 1024,
  },
};

vi.mock("../services/investigationService", () => ({
  getInvestigationStatus: vi.fn(() => Promise.resolve(statusState.payload)),
  startInvestigation: vi.fn(() =>
    Promise.resolve({
      investigation_id: "INV-TEST-1",
      status: "running",
      message: "Investigation started.",
    }),
  ),
  listInvestigations: vi.fn(() => Promise.resolve([])),
}));

function OtherPage() {
  return <div>Dashboard placeholder</div>;
}

/** App shell with sidebar-style links so navigation is a real route change. */
function TestApp({ initial }: { initial: string }) {
  return (
    <ToastProvider>
      <UploadProvider>
        <MemoryRouter initialEntries={[initial]}>
          <nav>
            <Link to="/upload">nav-upload</Link>
            <Link to="/dashboard">nav-dashboard</Link>
            <Link to="/investigation/INV-TEST-1">nav-investigation</Link>
          </nav>

          <Routes>
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/dashboard" element={<OtherPage />} />
            <Route
              path="/investigation/:investigationId"
              element={<InvestigationPage />}
            />
          </Routes>
        </MemoryRouter>
      </UploadProvider>
    </ToastProvider>
  );
}

beforeEach(() => {
  uploadState.resolve = null;
  uploadState.onProgress = null;
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("(a) upload survives navigating away and back", () => {
  test("in-flight upload and its percentage are still shown on return", async () => {
    const user = userEvent.setup();

    render(<TestApp initial="/upload" />);

    // Select a file and start the upload.
    const file = new File(["x".repeat(64)], "memory.raw", {
      type: "application/octet-stream",
    });

    const input = document.querySelector(
      'input[type="file"]',
    ) as HTMLInputElement;

    await user.upload(input, file);

    const uploadButton = await screen.findByRole("button", {
      name: /upload/i,
    });

    await user.click(uploadButton);

    // Transfer reaches 45% while the user is still on the page.
    await act(async () => {
      uploadState.onProgress?.(45);
    });

    expect(await screen.findByText("45%")).toBeTruthy();

    // Navigate away mid-transfer, exactly as clicking the sidebar does.
    await user.click(screen.getByText("nav-dashboard"));
    expect(screen.getByText("Dashboard placeholder")).toBeTruthy();

    // Transfer continues in the background while off-page.
    await act(async () => {
      uploadState.onProgress?.(72);
    });

    // Navigate back to the upload page.
    await user.click(screen.getByText("nav-upload"));

    // The in-flight upload must still be visible with live progress, rather
    // than a blank dropzone as if it never started.
    expect(await screen.findByText("72%")).toBeTruthy();
    expect(screen.getByText("memory.raw")).toBeTruthy();
  });
});

describe("(b) running investigation survives navigating away and back", () => {
  test("detail page re-fetches true backend state on return", async () => {
    const user = userEvent.setup();

    const { getInvestigationStatus } = await import(
      "../services/investigationService"
    );

    render(<TestApp initial="/investigation/INV-TEST-1" />);

    // Running analysis shown from backend state.
    expect(await screen.findByText("40%")).toBeTruthy();
    expect(
      screen.getByText(/4 of 10 plugins finished/i),
    ).toBeTruthy();

    const callsBefore = vi.mocked(getInvestigationStatus).mock.calls.length;

    // Navigate away, then back — a route change, not a reload.
    await user.click(screen.getByText("nav-dashboard"));
    expect(screen.getByText("Dashboard placeholder")).toBeTruthy();

    // Backend progressed while the user was elsewhere.
    statusState.payload = {
      ...statusState.payload,
      progress: 80,
      finished_plugins: 8,
      completed_plugins: 7,
      current_plugin: "windows.malfind",
    };

    await user.click(screen.getByText("nav-investigation"));

    // Must reflect current backend state, not a reset or the stale value.
    expect(await screen.findByText("80%")).toBeTruthy();
    expect(
      screen.getByText(/8 of 10 plugins finished/i),
    ).toBeTruthy();

    // And it genuinely re-queried the backend rather than rendering blank.
    await waitFor(() => {
      expect(
        vi.mocked(getInvestigationStatus).mock.calls.length,
      ).toBeGreaterThan(callsBefore);
    });
  });

  test("dump identity renders without router state", async () => {
    // Reaching the page by navigation carries no location.state, so the
    // filename and hash must come from the status response.
    render(<TestApp initial="/investigation/INV-TEST-1" />);

    expect(await screen.findByText("real-dump.raw")).toBeTruthy();
    expect(screen.getByText(/abc123def456/)).toBeTruthy();
  });
});
