import { Moon, Sun } from "lucide-react";

import { useTheme } from "../../theme/theme-context";

export default function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  const isLight = theme === "light";

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={isLight ? "Switch to dark theme" : "Switch to light theme"}
      title={isLight ? "Dark theme" : "Light theme"}
      className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-500"
    >
      {isLight ? <Moon size={16} /> : <Sun size={16} />}
      {isLight ? "Dark" : "Light"}
    </button>
  );
}