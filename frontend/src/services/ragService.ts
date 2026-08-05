import api from "./api";

import type {
  RAGIndexResponse,
  RAGSearchResponse,
} from "../types/rag";

export async function searchRag(
  query: string,
  investigationId?: string,
  topK = 10,
): Promise<RAGSearchResponse> {
  const params: Record<string, string | number> = {
    query,
    top_k: topK,
  };

  if (investigationId) {
    params.investigation_id = investigationId;
  }

  const response = await api.get<RAGSearchResponse>("/rag/search", {
    params,
  });

  return response.data;
}

export async function indexInvestigation(
  investigationId: string,
): Promise<RAGIndexResponse> {
  const response = await api.post<RAGIndexResponse>(
    `/rag/index/${investigationId}`,
  );

  return response.data;
}
