import { CalendarDays, FileArchive } from "lucide-react";

const investigations = [
  {
    name: "Windows10.raw",
    date: "30 Jul 2026",
    status: "Completed",
  },
  {
    name: "MalwareCase.mem",
    date: "29 Jul 2026",
    status: "Running",
  },
  {
    name: "ServerDump.raw",
    date: "28 Jul 2026",
    status: "Completed",
  },
];

export default function RecentInvestigations() {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

      <h2 className="mb-6 text-xl font-semibold text-white">
        Recent Investigations
      </h2>

      <div className="space-y-4">

        {investigations.map((item) => (
          <div
            key={item.name}
            className="flex items-center justify-between rounded-xl bg-slate-950 p-4"
          >
            <div className="flex items-center gap-4">

              <FileArchive
                className="text-cyan-400"
                size={22}
              />

              <div>

                <p className="font-medium text-white">
                  {item.name}
                </p>

                <div className="mt-1 flex items-center gap-2 text-sm text-slate-500">

                  <CalendarDays size={14} />

                  {item.date}

                </div>

              </div>

            </div>

            <span
              className={`rounded-full px-3 py-1 text-xs font-semibold ${
                item.status === "Completed"
                  ? "bg-green-500/20 text-green-400"
                  : "bg-yellow-500/20 text-yellow-400"
              }`}
            >
              {item.status}
            </span>
          </div>
        ))}

      </div>

    </div>
  );
}