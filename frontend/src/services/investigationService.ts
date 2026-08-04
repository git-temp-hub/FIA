import api from "./api";

export async function startInvestigation(
  investigationId: string,
  memoryDumpPath: string,
) {
  const response = await api.post("/investigation/start", {
    investigation_id: investigationId,
    memory_dump_path: memoryDumpPath,
  });

  return response.data;
}