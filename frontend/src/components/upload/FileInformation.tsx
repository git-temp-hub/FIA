interface Props {
  file: File;
}

export default function FileInformation({
  file,
}: Props) {
  return (
    <div className="rounded-2xl bg-slate-900 p-6">

      <h2 className="mb-4 text-xl font-semibold text-white">
        Selected File
      </h2>

      <div className="space-y-2 text-slate-300">

        <p>
          <strong>Name:</strong> {file.name}
        </p>

        <p>
          <strong>Size:</strong>{" "}
          {(file.size / 1024 / 1024).toFixed(2)} MB
        </p>

        <p>
          <strong>Type:</strong> {file.type || "Memory Dump"}
        </p>

      </div>

    </div>
  );
}