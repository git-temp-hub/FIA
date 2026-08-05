import api from "./api";

export interface InvestigationStartResult {
  investigation_id: string;
  status: string;
  message: string;
}

export interface InvestigationStatus {
  investigation_id: string;
  status: string;
  progress: number;
}

export async function startInvestigation(
  investigationId: string,
  memoryDumpPath: string,
): Promise<InvestigationStartResult> {
  const response = await api.post<InvestigationStartResult>(
    "/investigation/start",
    {
      investigation_id: investigationId,
      memory_dump_path: memoryDumpPath,
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
