import { useCallback, useMemo, useRef, useState, type ReactNode } from "react";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";

import {
  ToastContext,
  type ToastItem,
  type ToastType,
} from "./toast-context";

const TOAST_DURATION_MS = 4500;

const typeStyles: Record<ToastType, { bar: string; icon: ReactNode }> = {
  success: {
    bar: "bg-green-500",
    icon: <CheckCircle2 className="h-5 w-5 shrink-0 text-green-400" />,
  },
  error: {
    bar: "bg-red-500",
    icon: <AlertCircle className="h-5 w-5 shrink-0 text-red-400" />,
  },
  info: {
    bar: "bg-cyan-500",
    icon: <Info className="h-5 w-5 shrink-0 text-cyan-400" />,
  },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const removeToast = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (type: ToastType, message: string) => {
      const id = nextId.current;
      nextId.current += 1;

      setToasts((current) => [...current, { id, type, message }]);

      window.setTimeout(() => removeToast(id), TOAST_DURATION_MS);
    },
    [removeToast],
  );

  const success = useCallback(
    (message: string) => push("success", message),
    [push],
  );

  const error = useCallback(
    (message: string) => push("error", message),
    [push],
  );

  const info = useCallback(
    (message: string) => push("info", message),
    [push],
  );

  const value = useMemo(
    () => ({ success, error, info }),
    [success, error, info],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}

      <div
        className="pointer-events-none fixed right-4 top-4 z-50 flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-3"
        aria-live="polite"
      >
        {toasts.map((toast) => {
          const styles = typeStyles[toast.type];

          return (
            <div
              key={toast.id}
              className="pointer-events-auto relative overflow-hidden rounded-lg border border-slate-700 bg-slate-900 shadow-lg"
            >
              <div className="flex items-start gap-3 p-4">
                {styles.icon}

                <p className="flex-1 text-sm text-slate-200">
                  {toast.message}
                </p>

                <button
                  type="button"
                  onClick={() => removeToast(toast.id)}
                  className="text-slate-500 transition hover:text-slate-200"
                  aria-label="Dismiss notification"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div
                className={`h-1 w-full ${styles.bar}`}
                style={{
                  animation: `toast-dismiss ${TOAST_DURATION_MS}ms linear forwards`,
                }}
              />
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
