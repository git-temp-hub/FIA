interface Props {
  progress: number;
}

export default function UploadProgress({
  progress,
}: Props) {
  return (
    <div className="rounded-2xl bg-slate-900 p-6">

      <h2 className="mb-4 text-white">
        Upload Progress
      </h2>

      <div className="h-3 overflow-hidden rounded-full bg-slate-700">

        <div
          className="h-full bg-cyan-500 transition-all duration-300"
          style={{
            width: `${progress}%`,
          }}
        />

      </div>

      <p className="mt-3 text-cyan-400">

        {progress}%

      </p>

    </div>
  );
}