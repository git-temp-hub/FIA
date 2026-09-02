import { useCallback, useMemo, useRef, useState } from "react";

import { uploadMemoryDump } from "../services/uploadService";
import { getErrorMessage } from "../services/api";

import { UploadContext } from "./upload-context";
import type { ActiveUpload, UploadContextValue } from "./upload-context";

interface Props {
  children: React.ReactNode;
}

/**
 * Holds in-flight upload state above the router.
 *
 * The upload previously lived in UploadPage's local state, so navigating to
 * another page unmounted the component and the transfer vanished from the UI
 * (the XHR kept running, but nothing was left to render its progress).
 * Hosting the state here keeps a running upload visible no matter where the
 * user navigates, and lets the header surface it globally.
 */
export default function UploadProvider({ children }: Props) {
  const [upload, setUpload] = useState<ActiveUpload | null>(null);
  const [uploading, setUploading] = useState(false);

  // Guards against a second upload starting while one is in flight.
  const inFlight = useRef(false);

  const startUpload = useCallback(
    async (file: File): Promise<string | null> => {
      if (inFlight.current) return null;

      inFlight.current = true;
      setUploading(true);

      setUpload({
        filename: file.name,
        size: file.size,
        progress: 0,
        investigationId: null,
        error: null,
        done: false,
      });

      try {
        const response = await uploadMemoryDump(file, (progress) => {
          setUpload((current) =>
            current ? { ...current, progress } : current,
          );
        });

        setUpload({
          filename: response.filename,
          size: response.size,
          progress: 100,
          investigationId: response.investigation_id,
          error: null,
          done: true,
        });

        return response.investigation_id;
      } catch (err) {
        const detail = getErrorMessage(err);

        setUpload((current) =>
          current
            ? { ...current, error: detail, done: true }
            : {
                filename: file.name,
                size: file.size,
                progress: 0,
                investigationId: null,
                error: detail,
                done: true,
              },
        );

        return null;
      } finally {
        inFlight.current = false;
        setUploading(false);
      }
    },
    [],
  );

  const clearUpload = useCallback(() => {
    // Never discard an upload that is still transferring.
    if (inFlight.current) return;
    setUpload(null);
  }, []);

  const value = useMemo<UploadContextValue>(
    () => ({ upload, uploading, startUpload, clearUpload }),
    [upload, uploading, startUpload, clearUpload],
  );

  return (
    <UploadContext.Provider value={value}>{children}</UploadContext.Provider>
  );
}
