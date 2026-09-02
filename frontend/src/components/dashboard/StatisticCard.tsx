import type { LucideIcon } from "lucide-react";

export type StatAccent =
  | "cyan"
  | "violet"
  | "amber"
  | "emerald"
  | "rose"
  | "blue";

interface StatisticCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  icon: LucideIcon;
  accent?: StatAccent;
}

/**
 * Accent styles per tile.
 *
 * Written as complete literal class strings rather than interpolated
 * fragments so Tailwind's scanner can see every class it must emit.
 */
const ACCENTS: Record<StatAccent, { wrap: string; icon: string; bar: string }> =
  {
    cyan: {
      wrap: "bg-cyan-500/10 ring-cyan-500/20",
      icon: "text-cyan-400",
      bar: "bg-cyan-500",
    },
    violet: {
      wrap: "bg-violet-500/10 ring-violet-500/20",
      icon: "text-violet-400",
      bar: "bg-violet-500",
    },
    amber: {
      wrap: "bg-amber-500/10 ring-amber-500/20",
      icon: "text-amber-400",
      bar: "bg-amber-500",
    },
    emerald: {
      wrap: "bg-emerald-500/10 ring-emerald-500/20",
      icon: "text-emerald-400",
      bar: "bg-emerald-500",
    },
    rose: {
      wrap: "bg-rose-500/10 ring-rose-500/20",
      icon: "text-rose-400",
      bar: "bg-rose-500",
    },
    blue: {
      wrap: "bg-blue-500/10 ring-blue-500/20",
      icon: "text-blue-400",
      bar: "bg-blue-500",
    },
  };

export default function StatisticCard({
  title,
  value,
  subtitle,
  icon: Icon,
  accent = "cyan",
}: StatisticCardProps) {
  const theme = ACCENTS[accent];

  return (
    // h-full + flex column makes every card fill its grid row height, so the
    // accent bar always sits on the card's bottom edge regardless of how many
    // lines the subtitle wraps to.
    <div className="flex h-full flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 shadow-lg transition-all duration-300 hover:border-slate-700 hover:shadow-black/20">
      <div className="flex flex-1 items-start justify-between gap-4 p-6">
        {/* min-w-0 lets long values truncate instead of pushing the icon. */}
        <div className="flex min-w-0 flex-1 flex-col">
          <p className="text-sm uppercase tracking-wide text-slate-400">
            {title}
          </p>

          <h2 className="mt-3 truncate text-4xl font-bold text-white">
            {value}
          </h2>

          {/* mt-auto pins the subtitle to the bottom of the text column so
              tiles with one-line and two-line subtitles still line up. */}
          <p className="mt-auto pt-2 text-sm text-slate-500">{subtitle}</p>
        </div>

        {/* items-start above (not items-center) anchors the icon to the top
            of the card. Previously the icon was centred against a text column
            whose height varied with subtitle length, so icons sat at
            different heights across adjacent tiles. */}
        <div
          className={`shrink-0 rounded-xl p-4 ring-1 ${theme.wrap}`}
        >
          <Icon size={28} className={theme.icon} />
        </div>
      </div>

      <div className={`h-1 w-full ${theme.bar}`} />
    </div>
  );
}
