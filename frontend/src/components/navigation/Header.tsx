import { Menu } from "lucide-react";

import ThemeToggle from "../ui/ThemeToggle";
import ActiveWorkIndicator from "./ActiveWorkIndicator";
import SystemHealthIndicator from "./SystemHealthIndicator";

interface Props {
  onMenuClick: () => void;
}

export default function Header({ onMenuClick }: Props) {
  return (
    <header className="flex h-16 items-center justify-between gap-4 border-b border-slate-800 bg-slate-950 px-8">
      <div className="flex min-w-0 items-center gap-4">
        <button
          type="button"
          onClick={onMenuClick}
          className="rounded-lg p-2 text-slate-300 transition hover:bg-slate-800 hover:text-white md:hidden"
          aria-label="Open menu"
        >
          <Menu size={22} />
        </button>

        <div className="min-w-0">
          <h2 className="text-xl font-semibold text-white">ANVESHAK</h2>
          <p className="text-xs text-slate-500">
            AI Memory Forensic Investigation Assistant
          </p>
        </div>
      </div>

      {/* Health and theme live here so they are reachable from every page.
          Both were previously page-scoped: health was duplicated across the
          dashboard and settings, and the theme toggle existed only on the
          dashboard. */}
      <div className="flex shrink-0 items-center gap-3">
        {/* In-flight upload / running analysis, visible from every page. */}
        <ActiveWorkIndicator />
        <SystemHealthIndicator />
        <ThemeToggle />
      </div>
    </header>
  );
}
