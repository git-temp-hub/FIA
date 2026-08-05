import { useState } from "react";
import { useNavigate } from "react-router-dom";

import UploadDropzone from "../../components/upload/UploadDropzone";
import FileInformation from "../../components/upload/FileInformation";
import UploadProgress from "../../components/upload/UploadProgress";
import UploadActions from "../../components/upload/UploadActions";

import { uploadMemoryDump } from "../../services/uploadService";
import { getErrorMessage } from "../../services/api";
import { useToast } from "../../components/ui/toast-context";

export default function UploadPage() {
  const navigate = useNavigate();
  const toast = useToast();

  const [file, setFile] = useState<File>();
  const [progress, setProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleUpload() {
    if (!file || uploading) return;

    setUploading(true);
    setError(null);

    try {
      const response = await uploadMemoryDump(file, setProgress);

      toast.success(`Memory dump uploaded: ${response.filename}`);

      navigate("/investigation", {
        state: {
          investigation_id: response.investigation_id,
          stored_path: response.stored_path,
          filename: response.filename,
          size: response.size,
          sha256: response.sha256,
        },
      });
    } catch (err) {
      const detail = getErrorMessage(err);

      setError(detail);
      toast.error(detail);
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-4xl font-bold text-white">
          Upload Memory Dump
        </h1>

        <p className="mt-2 text-slate-400">
          Upload a forensic memory image for investigation.
        </p>
      </div>

      <UploadDropzone onFileSelect={setFile} />

      {file && <FileInformation file={file} />}

      {uploading && <UploadProgress progress={progress} />}

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <UploadActions
        disabled={!file || uploading}
        uploading={uploading}
        onUpload={handleUpload}
      />
    </div>
  );
}
