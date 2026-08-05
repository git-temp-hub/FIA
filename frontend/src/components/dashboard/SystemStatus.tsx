import {
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Database,
  Brain,
  Server,
} from "lucide-react";

import type { SystemHealth } from "../../types/dashboard";

interface SystemStatusProps {
  health: SystemHealth;
}

const OK_STATUSES = new Set(["connected", "ready", "online"]);

function statusLabel(service: string, status: string): string {
  if (service === "Backend API") return status ? "Online" : "Offline";

  if (status === "connected") return "Connected";
  if (status === "ready") return "Ready";
  return "Unavailable";
}

export default function SystemStatus({ health }: SystemStatusProps) {
  const services = [
    { icon: Server, name: "Backend API", status: "online" },
    { icon: Brain, name: "Ollama", status: health.ollama },
    { icon: Database, name: "SQLite", status: health.database },
    { icon: Cpu, name: "ChromaDB", status: health.chromadb },
  ];

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-6 text-xl font-semibold text-white">
        System Status
      </h2>

      <div className="space-y-4">
        {services.map((service) => {
          const Icon = service.icon;
          const ok = OK_STATUSES.has(service.status);

          return (
            <div
              key={service.name}
              className="flex items-center justify-between rounded-xl bg-slate-950 p-4"
            >
              <div className="flex items-center gap-3">
                <Icon className="text-cyan-400" size={22} />

                <span className="text-slate-200">{service.name}</span>
              </div>

              <div className="flex items-center gap-2">
                {ok ? (
                  <CheckCircle2 className="text-green-500" size={18} />
                ) : (
                  <AlertTriangle className="text-red-500" size={18} />
                )}

                <span className={ok ? "text-green-400" : "text-red-400"}>
                  {statusLabel(service.name, service.status)}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
