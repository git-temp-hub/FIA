import { useState } from "react";
import { NavLink } from "react-router-dom";
import {
  Bot,
  FileSearch,
  FileText,
  LayoutDashboard,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Upload,
  X,
} from "lucide-react";

const menu = [
  {
    name: "Dashboard",
    path: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    name: "Upload",
    path: "/upload",
    icon: Upload,
  },
  {
    name: "Investigations",
    path: "/investigation",
    icon: Search,
  },
  {
    name: "Evidence",
    path: "/evidence",
    icon: FileSearch,
  },
  {
    name: "Semantic Search",
    path: "/rag",
    icon: Sparkles,
  },
  {
    name: "AI Investigation",
    path: "/ai",
    icon: Bot,
  },
  {
    name: "Reports",
    path: "/reports",
    icon: FileText,
  },
  {
    name: "Settings",
    path: "/settings",
    icon: Settings,
  },
];

interface Props {
  mobileOpen: boolean;
  onClose: () => void;
}

export default function Sidebar({ mobileOpen, onClose }: Props) {
  const [expanded, setExpanded] = useState(false);

  const showLabels = expanded || mobileOpen;

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      <aside
        onMouseEnter={() => setExpanded(true)}
        onMouseLeave={() => setExpanded(false)}
        className={`fixed inset-y-0 left-0 z-40 flex flex-col border-r border-slate-800 bg-slate-900 transition-all duration-200 md:static md:translate-x-0 ${
          showLabels ? "w-72" : "w-20"
        } ${mobileOpen ? "translate-x-0" : "-translate-x-full"}`}
      >
        <div
          className={`flex border-b border-slate-800 ${
            showLabels ? "items-center gap-3 p-6" : "flex-col items-center gap-2 p-4"
          }`}
        >
          <ShieldCheck className="shrink-0 text-cyan-400" size={34} />

          {showLabels ? (
            <>
              <div className="min-w-0 flex-1">
                <h1 className="truncate text-lg font-bold text-white">
                  ANVESHAK
                </h1>
                <p className="truncate text-sm text-slate-400">
                  Evidence. Analysis. Intelligence.
                </p>
              </div>

              <button
                type="button"
                onClick={onClose}
                className="rounded-lg p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white md:hidden"
                aria-label="Close menu"
              >
                <X size={20} />
              </button>
            </>
          ) : (
            <span className="sr-only">ANVESHAK</span>
          )}
        </div>

        <nav className="flex-1 space-y-2 p-4">
          {menu.map((item) => {
            const Icon = item.icon;

            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={onClose}
                title={showLabels ? undefined : item.name}
                className={({ isActive }) =>
                  `relative flex items-center gap-3 rounded-xl px-4 py-3 transition ${
                    showLabels ? "" : "justify-center px-2"
                  } ${
                    isActive
                      ? "bg-cyan-500 font-semibold text-black"
                      : "text-slate-300 hover:bg-slate-800 hover:text-white"
                  }`
                }
              >
                <Icon size={20} className="shrink-0" />
                {showLabels && <span className="truncate">{item.name}</span>}

                {!showLabels && (
                  <span className="absolute left-1 top-1/2 h-6 w-1 -translate-y-1/2 rounded-r bg-cyan-400" />
                )}
              </NavLink>
            );
          })}
        </nav>

        {showLabels && (
          <div className="border-t border-slate-800 p-5">
            <p className="text-xs text-slate-500">
              AI Memory Forensic Investigation Assistant
            </p>
            <p className="mt-1 text-xs text-slate-600">Version 1.0 MVP</p>
          </div>
        )}
      </aside>
    </>
  );
}