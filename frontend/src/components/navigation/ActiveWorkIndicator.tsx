import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Loader2, Upload as UploadIcon } from "lucide-react";

import { listInvestigations } from "../../services/investigationService";
import { useUpload } from "../../upload/upload-context";
import type { InvestigationSummary } from "../../types/investigation";

const POLL_INTERVAL_MS = 4000;

/**
 * Header indicator for work in flight.
 *
 * Makes an active upload or a running investigation visible from every page,
 * so navigating away from the upload or investigation screen no longer means
 * losing sight of it. Running investigations are polled from the backend, so
 * this reflects true server state rather than anything held in the page the
 * user happened to start from.
 */
export default function ActiveWorkIndicator() {
  const { upload, uploading } = useUpload();

  const [running, setRunning] = useState<InvestigationSummary[]>([]);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const items = await listInvestigations();

        if (cancelled) return;

        setRunning(items.filter((item) => item.status === "running"));
      } catch {
        if (!cancelled) setRunning([]);
      }
    }

    poll();
    const timer = window.setInterval(poll, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  if (!uploading && running.length === 0) return null;

  return (
    <div className="flex items-center gap-2">
      {uploading && upload && (
        <Link
          to="/upload"
          className="inline-flex items-center gap-2 rounded-full border border-cyan-900 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-300 transition hover:border-cyan-500"
          title={`Uploading ${upload.filename}`}
        >
          <UploadIcon size={14} />
          <span className="hidden sm:inline">Uploading</span>
          <span className="font-mono">{upload.progress}%</span>
        </Link>
      )}

      {running.map((item) => (
        <Link
          key={item.investigation_id}
          to={`/investigation/${encodeURIComponent(item.investigation_id)}`}
          className="inline-flex items-center gap-2 rounded-full border border-amber-900 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-300 transition hover:border-amber-500"
          title={`${item.investigation_id} — analysis running`}
        >
          <Loader2 size={14} className="animate-spin" />
          <span className="hidden sm:inline">Analyzing</span>
          <span className="font-mono">{item.progress}%</span>
        </Link>
      ))}
    </div>
  );
}
