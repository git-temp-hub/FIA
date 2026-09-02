import { useEffect, useState } from "react";

import { listInvestigations } from "../../services/investigationService";
import type { InvestigationSummary } from "../../types/investigation";

interface Props {
  value: string;
  onChange: (investigationId: string) => void;
  label?: string;
  placeholder?: string;
  /** Show only investigations that already hold evidence. */
  requireEvidence?: boolean;
  className?: string;
  disabled?: boolean;
}

/**
 * Shared investigation selector.
 *
 * Replaces the four independent pickers that previously each fetched and
 * rendered their own investigation dropdown, so the list is fetched and
 * formatted one way across the app.
 */
export default function InvestigationPicker({
  value,
  onChange,
  label = "Investigation",
  placeholder = "Select an investigation",
  requireEvidence = false,
  className = "",
  disabled = false,
}: Props) {
  const [items, setItems] = useState<InvestigationSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    listInvestigations()
      .then((data) => {
        if (cancelled) return;
        setItems(
          requireEvidence
            ? data.filter((item) => item.evidence_count > 0)
            : data,
        );
      })
      .catch(() => {
        if (!cancelled) setItems([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [requireEvidence]);

  return (
    <div className={className}>
      {label && (
        <label className="mb-2 block text-sm font-medium text-slate-400">
          {label}
        </label>
      )}

      <select
        value={value}
        disabled={disabled || loading}
        onChange={(event) => onChange(event.target.value)}
        className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-3 text-white outline-none focus:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <option value="">
          {loading ? "Loading investigations..." : placeholder}
        </option>

        {items.map((item) => (
          <option key={item.investigation_id} value={item.investigation_id}>
            {item.investigation_id} — {item.filename}
            {item.evidence_count > 0
              ? ` (${item.evidence_count} artifacts)`
              : ""}
          </option>
        ))}
      </select>
    </div>
  );
}
