import api from "./api";
import type {
  ChatHistoryResponse,
  ChatQueryResponse,
} from "../types/chat";

export async function queryChat(
  investigationId: string,
  question: string,
  topK = 6,
): Promise<ChatQueryResponse> {
  const response = await api.post<ChatQueryResponse>("/chat/query", {
    investigation_id: investigationId,
    question,
    top_k: topK,
  });
  return response.data;
}

export async function getChatHistory(
  investigationId: string,
): Promise<ChatHistoryResponse> {
  const response = await api.get<ChatHistoryResponse>(
    `/chat/history/${encodeURIComponent(investigationId)}`,
  );
  return response.data;
}
