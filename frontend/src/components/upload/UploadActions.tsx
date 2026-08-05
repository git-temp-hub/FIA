import { Loader2 } from "lucide-react";

interface Props {
  disabled: boolean;
  uploading: boolean;
  onUpload: () => void;
}

export default function UploadActions({
  disabled,
  uploading,
  onUpload,
}: Props) {
  return (
    <button
      type="button"
      disabled={disabled || uploading}
      onClick={onUpload}
      className="flex items-center gap-2 rounded-xl bg-cyan-500 px-8 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-700"
    >
      {uploading && <Loader2 className="animate-spin" size={18} />}
      {uploading ? "Uploading..." : "Upload Memory Dump"}
    </button>
  );
}
