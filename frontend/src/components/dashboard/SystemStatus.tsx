import {
  CheckCircle2,
  Cpu,
  Database,
  Brain,
  Server,
} from "lucide-react";

const services = [
  {
    icon: Server,
    name: "Backend API",
    status: "Online",
  },
  {
    icon: Brain,
    name: "Ollama",
    status: "Connected",
  },
  {
    icon: Database,
    name: "SQLite",
    status: "Ready",
  },
  {
    icon: Cpu,
    name: "ChromaDB",
    status: "Ready",
  },
];

export default function SystemStatus() {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">

      <h2 className="mb-6 text-xl font-semibold text-white">
        System Status
      </h2>

      <div className="space-y-4">

        {services.map((service) => {

          const Icon = service.icon;

          return (
            <div
              key={service.name}
              className="flex items-center justify-between rounded-xl bg-slate-950 p-4"
            >

              <div className="flex items-center gap-3">

                <Icon
                  className="text-cyan-400"
                  size={22}
                />

                <span className="text-slate-200">
                  {service.name}
                </span>

              </div>

              <div className="flex items-center gap-2">

                <CheckCircle2
                  className="text-green-500"
                  size={18}
                />

                <span className="text-green-400">
                  {service.status}
                </span>

              </div>

            </div>
          );

        })}

      </div>

    </div>
  );
}