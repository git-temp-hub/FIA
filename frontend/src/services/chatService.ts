import api from "./api";
import type {
  ChatHistoryResponse,
  ChatQueryResponse,
} from "../types/chat";

export async function queryChat(
  investigationId: string,
  question: string,
  sessionId?: string | null,
  topK = 6,
): Promise<ChatQueryResponse> {
  const response = await api.post<ChatQueryResponse>("/chat/query", {
    investigation_id: investigationId,
    session_id: sessionId ?? undefined,
    question,
    top_k: topK,
  });
  return response.data;
}

export async function getChatHistory(
  investigationId: string,
  sessionId?: string | null,
): Promise<ChatHistoryResponse> {
  const response = await api.get<ChatHistoryResponse>(
    `/chat/history/${encodeURIComponent(investigationId)}`,
    {
      params: sessionId ? { session_id: sessionId } : undefined,
    },
  );
  return response.data;
}
