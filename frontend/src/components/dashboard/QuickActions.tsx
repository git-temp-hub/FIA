import {
  Upload,
  Search,
  Brain,
  FileText,
} from "lucide-react";

const actions = [
  {
    title: "New Investigation",
    icon: Upload,
  },
  {
    title: "Browse Evidence",
    icon: Search,
  },
  {
    title: "AI Chat",
    icon: Brain,
  },
  {
    title: "Generate Report",
    icon: FileText,
  },
];

export default function QuickActions() {
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
              className="rounded-xl border border-slate-800 bg-slate-950 p-6 transition hover:border-cyan-500 hover:bg-slate-800"
            >

              <Icon
                className="mx-auto mb-4 text-cyan-400"
                size={32}
              />

              <p className="text-center font-medium text-white">
                {action.title}
              </p>

            </button>
          );

        })}

      </div>

    </div>
  );
}