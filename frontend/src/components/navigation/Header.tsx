import { Menu } from "lucide-react";

interface Props {
  onMenuClick: () => void;
}

export default function Header({ onMenuClick }: Props) {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950 flex items-center justify-between gap-4 px-8">

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
          <h2 className="text-white text-xl font-semibold">
            ANVESHAK
          </h2>
          <p className="text-slate-500 text-xs">
            AI Memory Forensic Investigation Assistant
          </p>
        </div>

      </div>

      <div className="hidden text-sm text-slate-400 lg:block">
        Government Digital Forensics Group
      </div>

    </header>
  );
}