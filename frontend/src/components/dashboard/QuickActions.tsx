import { useNavigate } from "react-router-dom";
import {
  Upload,
  Search,
  Brain,
  FileText,
} from "lucide-react";

const actions = [
  {
    title: "New Investigation",
    description: "Upload a memory dump",
    path: "/upload",
    icon: Upload,
  },
  {
    title: "Browse Evidence",
    description: "Explore indexed artifacts",
    path: "/evidence",
    icon: Search,
  },
  {
    title: "AI Chat",
    description: "Ask the investigation assistant",
    path: "/ai",
    icon: Brain,
  },
  {
    title: "Generate Report",
    description: "Create a PDF report",
    path: "/reports",
    icon: FileText,
  },
];

export default function QuickActions() {
  const navigate = useNavigate();

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-6 text-xl font-semibold text-white">
        Quick Actions
      </h2>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {actions.map((action) => {
          const Icon = action.icon;

          return (
            <button
              key={action.title}
              type="button"
              onClick={() => navigate(action.path)}
              className="rounded-xl border border-slate-800 bg-slate-950 p-6 transition hover:border-cyan-500 hover:bg-slate-800"
            >
              <Icon className="mx-auto mb-4 text-cyan-400" size={32} />

              <p className="text-center font-medium text-white">
                {action.title}
              </p>

              <p className="mt-1 text-center text-sm text-slate-500">
                {action.description}
              </p>
            </button>
          );
        })}
      </div>
    </div>
  );
}
