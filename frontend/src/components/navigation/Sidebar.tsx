import {
  LayoutDashboard,
  Upload,
  Search,
  FileSearch,
  FileText,
  Settings,
  ShieldCheck,
} from "lucide-react";

import { NavLink } from "react-router-dom";

const menu = [
  {
    name: "Dashboard",
    path: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    name: "New Investigation",
    path: "/upload",
    icon: Upload,
  },
  {
    name: "Investigation",
    path: "/investigation",
    icon: Search,
  },
  {
    name: "Evidence",
    path: "/evidence",
    icon: FileSearch,
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

export default function Sidebar() {
  return (
    <aside className="w-72 bg-slate-900 border-r border-slate-800 flex flex-col">

      <div className="p-6 border-b border-slate-800">

        <div className="flex items-center gap-3">

          <ShieldCheck
            className="text-cyan-400"
            size={34}
          />

          <div>

            <h1 className="text-white text-lg font-bold">
              FIA
            </h1>

            <p className="text-slate-400 text-sm">
              Memory Forensics
            </p>

          </div>

        </div>

      </div>

      <nav className="flex-1 p-4 space-y-2">

        {menu.map((item) => {

          const Icon = item.icon;

          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-xl px-4 py-3 transition
                ${
                  isActive
                    ? "bg-cyan-500 text-black font-semibold"
                    : "text-slate-300 hover:bg-slate-800 hover:text-white"
                }`
              }
            >
              <Icon size={20} />

              {item.name}

            </NavLink>
          );
        })}

      </nav>

      <div className="border-t border-slate-800 p-5">

        <p className="text-slate-500 text-xs">

          AI Memory Forensic Investigation Assistant

        </p>

        <p className="text-slate-600 text-xs mt-1">

          Version 1.0 MVP

        </p>

      </div>

    </aside>
  );
}