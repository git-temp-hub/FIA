interface Props {
  disabled: boolean;
  onUpload: () => void;
}

export default function UploadActions({
  disabled,
  onUpload,
}: Props) {
  return (
    <button
      disabled={disabled}
      onClick={onUpload}
      className="rounded-xl bg-cyan-500 px-8 py-3 font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-700"
    >
      Upload Memory Dump
    </button>
  );
}