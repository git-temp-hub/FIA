import { useEffect, useRef, useState } from "react";

import type { FormEvent } from "react";

import { useSearchParams } from "react-router-dom";

import {
  AlertCircle,
  Bot,
  Loader2,
  Plus,
  Send,
  ShieldCheck,
  User,
} from "lucide-react";

import { getChatHistory, queryChat } from "../../services/chatService";
import {
  getOrCreateSessionId,
  getStoredSessionId,
  startSession,
} from "../../services/chatSession";
import { listEvidenceInvestigations } from "../../services/evidenceService";

import type { EvidenceInvestigationSummary } from "../../types/evidence";
import type { EvidenceReference } from "../../types/chat";

interface ChatMessageView {
  id: string;
  role: "user" | "assistant";
  content: string;
  confidence?: number | null;
  citations?: EvidenceReference[];
  createdAt?: string;
}

function confidenceStyle(confidence: number): string {
  if (confidence >= 70) return "bg-green-500/20 text-green-400";
  if (confidence >= 40) return "bg-yellow-500/20 text-yellow-400";
  return "bg-red-500/20 text-red-400";
}

function CitationCard({ reference }: { reference: EvidenceReference }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-full bg-cyan-500/20 px-2 py-0.5 font-mono text-xs font-semibold text-cyan-400">
          [#{reference.index}]
        </span>

        {reference.plugin_name && (
          <span className="rounded-full bg-slate-700/60 px-2 py-0.5 font-mono text-xs text-slate-300">
            {reference.plugin_name}
          </span>
        )}

        {reference.artifact_type && (
          <span className="rounded-full bg-slate-700/60 px-2 py-0.5 text-xs text-slate-300">
            {reference.artifact_type}
          </span>
        )}

        {reference.confidence_score !== null && (
          <span className="rounded-full bg-slate-700/60 px-2 py-0.5 text-xs text-slate-300">
            confidence {reference.confidence_score}%
          </span>
        )}

        {reference.score !== null && reference.score !== undefined && (
          <span className="rounded-full bg-slate-700/60 px-2 py-0.5 text-xs text-slate-300">
            {Math.round(reference.score * 100)}% similarity
          </span>
        )}
      </div>

      <p className="mt-2 break-words whitespace-pre-wrap text-xs leading-relaxed text-slate-400">
        {reference.document.length > 320
          ? `${reference.document.slice(0, 320)}...`
          : reference.document}
      </p>
    </div>
  );
}

function MessageBubble({ message }: { message: ChatMessageView }) {
  const isUser = message.role === "user";

  if (isUser) {
    return (
      <div className="flex items-start justify-end gap-3">
        <div className="max-w-[75%] rounded-2xl rounded-tr-sm bg-cyan-500 px-4 py-3 text-sm text-black">
          {message.content}
        </div>

        <div className="mt-1 rounded-full bg-slate-800 p-2 text-cyan-400">
          <User size={16} />
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-start gap-3">
      <div className="rounded-full bg-slate-800 p-2 text-cyan-400">
        <Bot size={16} />
      </div>

      <div className="max-w-[75%] space-y-3">
        <div className="rounded-2xl rounded-tl-sm border border-slate-700 bg-slate-900 px-4 py-3">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Assistant
            </span>

            {message.confidence !== null &&
              message.confidence !== undefined && (
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-semibold ${confidenceStyle(
                    message.confidence,
                  )}`}
                >
                  confidence {message.confidence}%
                </span>
              )}
          </div>

          <p className="whitespace-pre-wrap break-words text-sm leading-relaxed text-slate-100">
            {message.content}
          </p>
        </div>

        {message.citations && message.citations.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-medium text-slate-500">
              Supporting evidence
            </p>

            {message.citations.map((reference) => (
              <CitationCard
                key={reference.index}
                reference={reference}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ChatPage() {
  const [searchParams] = useSearchParams();

  const [investigations, setInvestigations] = useState<
    EvidenceInvestigationSummary[]
  >([]);

  const [investigationId, setInvestigationId] = useState(
    searchParams.get("id") ?? "",
  );

  const [sessionId, setSessionId] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const [messages, setMessages] = useState<ChatMessageView[]>([]);
  const [question, setQuestion] = useState("");

  const [sending, setSending] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const counterRef = useRef(0);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  function nextId(): string {
    counterRef.current += 1;
    return `m-${counterRef.current}`;
  }

  useEffect(() => {
    listEvidenceInvestigations()
      .then(setInvestigations)
      .catch(() => setInvestigations([]));
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      setMessages([]);
      setError(null);

      if (!investigationId) {
        setSessionId(null);
        setLoadingHistory(false);
        return;
      }

      const activeSession = getOrCreateSessionId(investigationId);
      setSessionId(activeSession);

      setLoadingHistory(true);

      getChatHistory(investigationId, activeSession)
        .then((response) => {
          setMessages(
            response.messages.map((message) => ({
              id: `h-${message.id}`,
              role: message.role === "assistant" ? "assistant" : "user",
              content: message.content,
              confidence: message.confidence,
              citations: message.citations ?? undefined,
              createdAt: message.created_at,
            })),
          );
        })
        .catch(() => setMessages([]))
        .finally(() => setLoadingHistory(false));
    }, 0);

    return () => clearTimeout(timer);
  }, [investigationId, reloadKey]);

  function handleNewSession() {
    if (!investigationId) return;

    startSession(investigationId);
    setSessionId(getStoredSessionId(investigationId));
    setMessages([]);
    setReloadKey((key) => key + 1);
  }

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, sending]);

  async function handleSend(event?: FormEvent) {
    event?.preventDefault();

    const trimmed = question.trim();
    if (!trimmed || !investigationId || sending) return;

    const activeSession =
      sessionId ?? getOrCreateSessionId(investigationId);

    setQuestion("");
    setError(null);

    setMessages((previous) => [
      ...previous,
      { id: nextId(), role: "user", content: trimmed },
    ]);

    setSending(true);

    try {
      const response = await queryChat(
        investigationId,
        trimmed,
        activeSession,
      );

      setMessages((previous) => [
        ...previous,
        {
          id: nextId(),
          role: "assistant",
          content: response.answer,
          confidence: response.confidence,
          citations: response.citations,
        },
      ]);
    } catch {
      setMessages((previous) => [
        ...previous,
        {
          id: nextId(),
          role: "assistant",
          content:
            "Sorry, the assistant could not answer your question. " +
            "Make sure the investigation has been indexed and the " +
            "LLM service (Ollama) is running.",
        },
      ]);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="flex h-full flex-col space-y-6">
      <div className="flex items-center gap-3">
        <Bot className="text-cyan-400" size={32} />

        <div>
          <h1 className="text-4xl font-bold text-white">
            AI Investigation
          </h1>

          <p className="mt-2 text-slate-400">
            Ask questions about an investigation; answers cite retrieved
            forensic evidence.
          </p>
        </div>
      </div>

      <div>
        <label className="mb-2 block text-sm font-medium text-slate-400">
          Investigation
        </label>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={investigationId}
            onChange={(event) => setInvestigationId(event.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-3 text-white outline-none focus:border-cyan-500 md:w-[480px]"
          >
            <option value="">
              Select an investigation to begin chatting
            </option>

            {investigations.map((item) => (
              <option
                key={item.investigation_id}
                value={item.investigation_id}
              >
                {item.investigation_id} — {item.filename}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={handleNewSession}
            disabled={!investigationId || sending}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm font-medium text-slate-300 transition hover:bg-slate-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Plus size={16} />
            New Session
          </button>
        </div>
      </div>

      <div className="flex min-h-[55vh] flex-col rounded-xl border border-slate-800 bg-slate-900/50">
        <div className="flex-1 space-y-4 overflow-y-auto p-5">
          {!investigationId ? (
            <div className="flex flex-col items-center gap-3 py-16 text-slate-500">
              <ShieldCheck size={28} />
              <p>
                Select an investigation to start asking questions.
              </p>
            </div>
          ) : loadingHistory ? (
            <div className="flex items-center justify-center gap-3 py-16 text-slate-400">
              <Loader2 className="animate-spin" size={20} />
              Loading conversation history...
            </div>
          ) : messages.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-16 text-slate-500">
              <Bot size={28} />
              <p>
                Ask a question such as "Which processes are running
                suspicious commands?" or "Are there any malicious
                connections?"
              </p>
            </div>
          ) : (
            messages.map((message) => (
              <MessageBubble
                key={message.id}
                message={message}
              />
            ))
          )}

          {sending && (
            <div className="flex items-start gap-3">
              <div className="rounded-full bg-slate-800 p-2 text-cyan-400">
                <Bot size={16} />
              </div>

              <div className="flex items-center gap-2 rounded-2xl rounded-tl-sm border border-slate-700 bg-slate-900 px-4 py-3">
                <Loader2 className="animate-spin text-cyan-400" size={16} />

                <span className="text-sm text-slate-400">
                  Consulting evidence...
                </span>
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        <div className="border-t border-slate-800 p-4">
          {error && (
            <div className="mb-3 flex items-center gap-2 text-sm text-red-400">
              <AlertCircle size={16} />
              <p>{error}</p>
            </div>
          )}

          <form
            onSubmit={handleSend}
            className="flex items-center gap-3"
          >
            <input
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder={
                investigationId
                  ? "Ask a question about this investigation..."
                  : "Select an investigation first"
              }
              disabled={!investigationId || sending}
              className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
            />

            <button
              type="submit"
              disabled={!question.trim() || !investigationId || sending}
              className="flex items-center gap-2 rounded-lg bg-cyan-500 px-6 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Send size={16} />
              Ask
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
