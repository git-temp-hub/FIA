import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, CheckCircle2, FileArchive, Play } from "lucide-react";

import UploadDropzone from "../../components/upload/UploadDropzone";
import FileInformation from "../../components/upload/FileInformation";
import UploadProgress from "../../components/upload/UploadProgress";
import UploadActions from "../../components/upload/UploadActions";

import { useUpload } from "../../upload/upload-context";
import { useToast } from "../../components/ui/toast-context";
import { listInvestigations } from "../../services/investigationService";
import type { InvestigationSummary } from "../../types/investigation";

export default function UploadPage() {
  const navigate = useNavigate();
  const toast = useToast();

  const { upload, uploading, startUpload, clearUpload } = useUpload();

  const [file, setFile] = useState<File>();

  // Tracks whether the user is still on this page when the upload finishes.
  // If they navigated away mid-transfer, completing the upload must not yank
  // them to the investigation page.
  const onPage = useRef(true);

  useEffect(() => {
    onPage.current = true;
    return () => {
      onPage.current = false;
    };
  }, []);

  // Dumps that finished uploading but were never analyzed, read from the
  // backend. Client-side upload state is memory-only: a reload, a crash, or
  // a hot-reload in dev discards it while the transfer keeps running
  // server-side, which previously left a completed upload with no visible
  // next step. Sourcing this from the server makes the next action
  // recoverable no matter what happened to the page.
  const [awaiting, setAwaiting] = useState<InvestigationSummary[]>([]);

  useEffect(() => {
    let cancelled = false;

    function load() {
      listInvestigations()
        .then((items) => {
          if (cancelled) return;
          setAwaiting(items.filter((item) => item.status === "uploaded"));
        })
        .catch(() => {
          if (!cancelled) setAwaiting([]);
        });
    }

    load();

    // Refresh while a transfer is in flight so the entry appears as soon as
    // the server finishes writing the dump, even if the response to this
    // browser was lost.
    const timer = window.setInterval(load, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [uploading]);

  async function handleUpload() {
    if (!file || uploading) return;

    const investigationId = await startUpload(file);

    if (!investigationId) return;

    toast.success(`Memory dump uploaded: ${file.name}`);

    if (onPage.current) {
      navigate(`/investigation/${encodeURIComponent(investigationId)}`, {
        state: {
          investigation_id: investigationId,
          filename: file.name,
          size: file.size,
        },
      });
    }
  }

  const showError = upload?.error ?? null;

  // A finished upload the user navigated back to, rather than one that just
  // completed under them.
  const completedEarlier = Boolean(
    upload?.done && upload.investigationId,
  );

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold text-white">Upload Memory Dump</h1>

        <p className="mt-2 text-slate-400">
          Upload a forensic memory image for investigation.
        </p>
      </div>

      {/* An upload in flight is rendered from shared state, so leaving the
          page and returning shows the live transfer rather than a blank
          form. */}
      {uploading && upload ? (
        <div className="space-y-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
            <p className="text-sm uppercase tracking-wide text-slate-500">
              Uploading
            </p>
            <p className="mt-2 truncate text-lg font-medium text-white">
              {upload.filename}
            </p>
          </div>

          <UploadProgress progress={upload.progress} />

          <p className="text-sm text-slate-500">
            You can navigate away — this upload continues in the background
            and stays visible in the header.
          </p>
        </div>
      ) : completedEarlier && upload ? (
        <div className="rounded-2xl border border-green-800 bg-slate-900 p-6">
          <div className="flex items-center gap-4">
            <CheckCircle2 className="shrink-0 text-green-400" size={26} />

            <div className="min-w-0">
              <p className="font-medium text-white">
                Upload complete: {upload.filename}
              </p>
              <p className="mt-1 font-mono text-sm text-cyan-400">
                {upload.investigationId}
              </p>
            </div>
          </div>

          <div className="mt-6 flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() =>
                navigate(
                  `/investigation/${encodeURIComponent(
                    upload.investigationId ?? "",
                  )}`,
                )
              }
              className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-5 py-2.5 font-semibold text-black transition hover:bg-cyan-400"
            >
              Go to investigation
              <ArrowRight size={16} />
            </button>

            <button
              type="button"
              onClick={() => {
                clearUpload();
                setFile(undefined);
              }}
              className="rounded-lg border border-slate-700 px-5 py-2.5 font-medium text-slate-200 transition hover:border-cyan-500"
            >
              Upload another
            </button>
          </div>
        </div>
      ) : (
        <>
          <UploadDropzone onFileSelect={setFile} />

          {file && <FileInformation file={file} />}

          {showError && (
            <div className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-400">
              {showError}
            </div>
          )}

          <UploadActions
            disabled={!file || uploading}
            uploading={uploading}
            onUpload={handleUpload}
          />
        </>
      )}

      {awaiting.length > 0 && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-xl font-semibold text-white">
            Uploaded, awaiting analysis
          </h2>

          <p className="mt-1 text-sm text-slate-500">
            These dumps are stored on the server and ready to analyze.
          </p>

          <div className="mt-5 space-y-3">
            {awaiting.map((item) => (
              <div
                key={item.investigation_id}
                className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-950 p-4"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <FileArchive className="shrink-0 text-cyan-400" size={22} />

                  <div className="min-w-0">
                    <p className="truncate font-medium text-white">
                      {item.filename}
                    </p>
                    <p className="mt-0.5 font-mono text-xs text-slate-500">
                      {item.investigation_id}
                    </p>
                  </div>
                </div>

                <Link
                  to={`/investigation/${encodeURIComponent(
                    item.investigation_id,
                  )}`}
                  className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-black transition hover:bg-cyan-400"
                >
                  <Play size={15} />
                  Start Investigation
                </Link>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
