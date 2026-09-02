import api from "./api";
import type {
  InvestigationListResponse,
  InvestigationSummary,
} from "../types/investigation";

export interface InvestigationStartResult {
  investigation_id: string;
  status: string;
  message: string;
}

export interface InvestigationStatus {
  investigation_id: string;
  status: string;
  /** Percentage of scheduled plugins that have finished, pass or fail. */
  progress: number;
  phase?: string | null;
  current_plugin?: string | null;
  /** Plugins scheduled for this run; stable for the whole run. */
  total_plugins?: number;
  /** Plugins that stopped running, regardless of outcome. */
  finished_plugins?: number;
  completed_plugins?: number;
  failed_plugins?: number;
  estimated_seconds_remaining?: number | null;
  last_error?: string | null;
  /** Dump identity, so a client can render the page from this alone. */
  filename?: string | null;
  sha256?: string | null;
  file_size?: number | null;
}

export async function startInvestigation(
  investigationId: string,
  memoryDumpPath?: string | null,
): Promise<InvestigationStartResult> {
  // The path is only needed for an investigation the backend has no record
  // of; for a known one the stored path is resolved server-side, so a page
  // reached by navigation (with no router state) can still start a run.
  const response = await api.post<InvestigationStartResult>(
    "/investigation/start",
    {
      investigation_id: investigationId,
      ...(memoryDumpPath ? { memory_dump_path: memoryDumpPath } : {}),
    },
  );

  return response.data;
}

export async function getInvestigationStatus(
  investigationId: string,
): Promise<InvestigationStatus> {
  const response = await api.get<InvestigationStatus>(
    `/investigation/status/${investigationId}`,
  );

  return response.data;
}

export async function listInvestigations(): Promise<InvestigationSummary[]> {
  const response = await api.get<InvestigationListResponse>("/investigation");

  return response.data.items;
}
