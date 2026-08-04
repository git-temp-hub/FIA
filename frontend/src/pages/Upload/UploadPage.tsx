import { useState } from "react";

import UploadDropzone from "../../components/upload/UploadDropzone";
import FileInformation from "../../components/upload/FileInformation";
import UploadProgress from "../../components/upload/UploadProgress";
import UploadActions from "../../components/upload/UploadActions";

import { uploadMemoryDump } from "../../services/uploadService";

export default function UploadPage() {

  const [file, setFile] = useState<File>();

  const [progress, setProgress] = useState(0);

  const [uploading, setUploading] = useState(false);

  async function handleUpload() {

    if (!file) return;

    setUploading(true);

    try {

      const response = await uploadMemoryDump(
        file,
        setProgress,
      );

      alert(
        `Upload completed!\n\n${response.filename}`,
      );

    } catch (error) {

      alert("Upload failed.");

      console.error(error);

    }

    setUploading(false);
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

      <UploadDropzone
        onFileSelect={setFile}
      />

      {file && (

        <FileInformation
          file={file}
        />

      )}

      {uploading && (

        <UploadProgress
          progress={progress}
        />

      )}

      <UploadActions
        disabled={!file || uploading}
        onUpload={handleUpload}
      />

    </div>

  );
}