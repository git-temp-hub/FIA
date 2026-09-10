import api, { API_BASE_URL } from "./api";
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

/**
 * Ask a question and receive the answer as it is generated.
 *
 * `onToken` fires with each chunk so the answer can be rendered
 * progressively. The value it accumulates is provisional: confidence
 * calibration, citation parsing and the corroboration and malfind ceilings
 * can only run on the finished text, so the server applies them after
 * generation and sends the authoritative version in a single terminal
 * event. That is what this resolves with, and what callers should display
 * once it arrives.
 */
export async function streamChat(
  investigationId: string,
  question: string,
  sessionId: string | null | undefined,
  onToken: (chunk: string) => void,
  topK = 6,
  onPhase?: (phase: string) => void,
): Promise<ChatQueryResponse> {
  const response = await fetch(`${API_BASE_URL}/chat/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      investigation_id: investigationId,
      session_id: sessionId ?? undefined,
      question,
      top_k: topK,
    }),
  });

  if (!response.ok || !response.body) {
    throw new Error(
      response.status === 404
        ? "Investigation not found."
        : `Request failed with status ${response.status}.`,
    );
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  let buffer = "";
  let result: ChatQueryResponse | null = null;
  let failure: string | null = null;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });

    // Events are separated by a blank line; a partial one stays buffered.
    const blocks = buffer.split("\n\n");
    buffer = blocks.pop() ?? "";

    for (const block of blocks) {
      if (!block.trim()) continue;

      let name = "message";
      const dataLines: string[] = [];

      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) name = line.slice(6).trim();
        else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
      }

      if (dataLines.length === 0) continue;

      let payload: unknown;
      try {
        payload = JSON.parse(dataLines.join("\n"));
      } catch {
        continue;
      }

      if (name === "token") {
        onToken((payload as { text: string }).text ?? "");
      } else if (name === "status") {
        onPhase?.((payload as { phase?: string }).phase ?? "");
      } else if (name === "result") {
        result = payload as ChatQueryResponse;
      } else if (name === "error") {
        failure = (payload as { detail?: string }).detail ?? "Generation failed.";
      }
    }
  }

  if (failure) throw new Error(failure);

  if (!result) {
    // The stream ended without the terminal event, so no calibrated
    // confidence or parsed citations exist. Whatever was rendered so far is
    // unverified, and callers must not present it as a finished answer.
    throw new Error(
      "The answer was cut off before it could be checked against the evidence.",
    );
  }

  return result;
}
