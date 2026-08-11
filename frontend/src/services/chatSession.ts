const STORAGE_PREFIX = "fia.chat.session.";

function storageKey(investigationId: string): string {
  return `${STORAGE_PREFIX}${investigationId}`;
}

export function generateSessionId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }

  return `sess-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export function getStoredSessionId(
  investigationId: string,
): string | null {
  try {
    return window.localStorage.getItem(storageKey(investigationId));
  } catch {
    return null;
  }
}

export function startSession(investigationId: string): string {
  const sessionId = generateSessionId();

  try {
    window.localStorage.setItem(storageKey(investigationId), sessionId);
  } catch {
    // Storage may be unavailable; the in-memory session still works.
  }

  return sessionId;
}

export function getOrCreateSessionId(investigationId: string): string {
  const existing = getStoredSessionId(investigationId);

  if (existing) {
    return existing;
  }

  return startSession(investigationId);
}
