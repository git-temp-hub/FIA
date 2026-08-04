import { UploadCloud } from "lucide-react";

interface Props {
  onFileSelect: (file: File) => void;
}

export default function UploadDropzone({
  onFileSelect,
}: Props) {
  return (
    <label className="flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-cyan-500 bg-slate-900 p-16 transition hover:bg-slate-800">

      <UploadCloud
        size={60}
        className="mb-4 text-cyan-400"
      />

      <h2 className="text-2xl font-semibold text-white">
        Drag & Drop Memory Dump
      </h2>

      <p className="mt-2 text-slate-400">
        or click to browse
      </p>

      <input
        hidden
        type="file"
        accept=".raw,.mem,.bin,.dmp,.img"
        onChange={(e) => {
          if (!e.target.files?.length) return;

          onFileSelect(e.target.files[0]);
        }}
      />

    </label>
  );
}