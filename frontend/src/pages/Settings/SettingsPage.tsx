import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Brain,
  Database,
  HardDrive,
  Info,
  Loader2,
  Puzzle,
  RefreshCw,
  Save,
} from "lucide-react";

import {
  getPlatformSettings,
  updatePlatformSettings,
} from "../../services/settingsService";
import { getErrorMessage } from "../../services/api";
import { useToast } from "../../components/ui/toast-context";

import type { PlatformSettings } from "../../types/settings";

interface SettingsCardProps {
  icon: typeof Database;
  title: string;
  description?: string;
  children: React.ReactNode;
}

function SettingsCard({
  icon: Icon,
  title,
  description,
  children,
}: SettingsCardProps) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-4 flex items-start gap-3">
        <span className="mt-0.5 shrink-0 rounded-lg bg-cyan-500/10 p-2">
          <Icon className="text-cyan-400" size={18} />
        </span>

        <div className="min-w-0">
          <h2 className="text-xl font-semibold text-white">{title}</h2>

          {description && (
            <p className="mt-1 text-sm text-slate-500">{description}</p>
          )}
        </div>
      </div>

      {children}
    </div>
  );
}

function FieldLabel({
  label,
  hint,
}: {
  label: string;
  hint?: string;
}) {
  return (
    <div className="mb-2">
      <label className="block text-sm font-medium text-slate-300">
        {label}
      </label>
      {hint && <p className="mt-0.5 text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

const inputClass =
  "w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-white outline-none focus:border-cyan-500";

export default function SettingsPage() {
  const toast = useToast();

  const [settings, setSettings] = useState<PlatformSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Draft state, initialised from the server and saved back on submit.
  const [plugins, setPlugins] = useState<string[]>([]);
  const [timeout, setTimeoutSeconds] = useState(1800);
  const [concurrency, setConcurrency] = useState(4);
  const [maxUploadGb, setMaxUploadGb] = useState(64);
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");

  function hydrate(data: PlatformSettings) {
    setSettings(data);
    setPlugins(data.analysis.plugins);
    setTimeoutSeconds(data.analysis.plugin_timeout_seconds);
    setConcurrency(data.analysis.max_concurrency);
    setMaxUploadGb(data.upload.max_dump_size_gb);
    setModel(data.llm.model);
    setBaseUrl(data.llm.base_url);
  }

  async function load() {
    setLoading(true);
    setError(null);

    try {
      hydrate(await getPlatformSettings());
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  // The initial fetch resolves state from the promise callbacks rather than
  // calling `load()` synchronously, which would setState during the effect
  // body and trigger a cascading render.
  useEffect(() => {
    let cancelled = false;

    getPlatformSettings()
      .then((data) => {
        if (!cancelled) hydrate(data);
      })
      .catch((err) => {
        if (!cancelled) setError(getErrorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  function togglePlugin(name: string) {
    setPlugins((current) =>
      current.includes(name)
        ? current.filter((item) => item !== name)
        : [...current, name],
    );
  }

  async function handleSave() {
    if (saving) return;

    if (plugins.length === 0) {
      toast.error("Select at least one plugin.");
      return;
    }

    setSaving(true);
    setError(null);

    try {
      const updated = await updatePlatformSettings({
        analysis: {
          plugins,
          plugin_timeout_seconds: timeout,
          max_concurrency: concurrency,
        },
        upload: { max_dump_size_gb: maxUploadGb },
        llm: { model, base_url: baseUrl },
      });

      hydrate(updated);
      toast.success("Settings saved.");
    } catch (err) {
      const detail = getErrorMessage(err);
      setError(detail);
      toast.error(detail);
    } finally {
      setSaving(false);
    }
  }

  const shadowed = new Set(settings?.env_shadowed ?? []);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-4xl font-bold text-white">Settings</h1>

          <p className="mt-2 text-slate-400">
            Platform configuration. Changes are written to config.yaml and
            take effect without restarting the backend.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={load}
            disabled={loading || saving}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 transition hover:border-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Reload
          </button>

          <button
            type="button"
            onClick={handleSave}
            disabled={loading || saving || !settings}
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-5 py-2 text-sm font-semibold text-black transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {saving ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            {saving ? "Saving..." : "Save Changes"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {loading && !settings ? (
        <div className="flex items-center justify-center gap-3 rounded-2xl border border-slate-800 bg-slate-900 py-20 text-slate-400">
          <Loader2 className="animate-spin" size={20} />
          Loading settings...
        </div>
      ) : settings ? (
        <>
          <SettingsCard
            icon={Puzzle}
            title="Plugin Selection"
            description="Volatility plugins executed for every new investigation."
          >
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
              {settings.available_plugins.map((name) => (
                <label
                  key={name}
                  className="flex cursor-pointer items-center gap-3 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2.5 transition hover:border-slate-700"
                >
                  <input
                    type="checkbox"
                    checked={plugins.includes(name)}
                    onChange={() => togglePlugin(name)}
                    className="h-4 w-4 accent-cyan-500"
                  />

                  <span className="truncate font-mono text-sm text-slate-200">
                    {name}
                  </span>
                </label>
              ))}
            </div>

            <p className="mt-3 text-xs text-slate-500">
              {plugins.length} of {settings.available_plugins.length} selected
            </p>
          </SettingsCard>

          <div className="grid gap-6 xl:grid-cols-2">
            <SettingsCard
              icon={Database}
              title="Analysis Limits"
              description="Applied to the next investigation that starts."
            >
              <div className="space-y-5">
                <div>
                  <FieldLabel
                    label="Per-plugin timeout (seconds)"
                    hint="A plugin exceeding this is killed and recorded as failed. 30–86400."
                  />
                  <input
                    type="number"
                    min={30}
                    max={86400}
                    value={timeout}
                    onChange={(event) =>
                      setTimeoutSeconds(Number(event.target.value))
                    }
                    className={inputClass}
                  />
                </div>

                <div>
                  <FieldLabel
                    label="Max concurrent plugins"
                    hint="How many plugins run in parallel. 1–32."
                  />
                  <input
                    type="number"
                    min={1}
                    max={32}
                    value={concurrency}
                    onChange={(event) =>
                      setConcurrency(Number(event.target.value))
                    }
                    className={inputClass}
                  />
                </div>

                <div>
                  <FieldLabel
                    label="Maximum upload size (GB)"
                    hint="Enforced while the dump streams in. 1–1024."
                  />
                  <input
                    type="number"
                    min={1}
                    max={1024}
                    value={maxUploadGb}
                    onChange={(event) =>
                      setMaxUploadGb(Number(event.target.value))
                    }
                    className={inputClass}
                  />
                </div>
              </div>
            </SettingsCard>

            <SettingsCard
              icon={Brain}
              title="Language Model"
              description="Ollama connection used for evidence-backed answers."
            >
              <div className="space-y-5">
                <div>
                  <FieldLabel label="Model" hint="e.g. qwen3:14b" />
                  <input
                    value={model}
                    onChange={(event) => setModel(event.target.value)}
                    className={inputClass}
                  />
                  {shadowed.has("llm.model") && (
                    <p className="mt-2 flex items-start gap-2 text-xs text-amber-400">
                      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                      LLM_MODEL is set in .env and overrides this value until
                      it is removed.
                    </p>
                  )}
                </div>

                <div>
                  <FieldLabel
                    label="Ollama host"
                    hint="Base URL, e.g. http://localhost:11434"
                  />
                  <input
                    value={baseUrl}
                    onChange={(event) => setBaseUrl(event.target.value)}
                    className={inputClass}
                  />
                  {shadowed.has("llm.base_url") && (
                    <p className="mt-2 flex items-start gap-2 text-xs text-amber-400">
                      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                      OLLAMA_HOST is set in .env and overrides this value
                      until it is removed.
                    </p>
                  )}
                </div>
              </div>
            </SettingsCard>
          </div>

          <SettingsCard
            icon={HardDrive}
            title="Storage Locations"
            description="Read-only. Changing these at runtime would orphan stored evidence and reports."
          >
            <div className="space-y-2">
              {(
                [
                  ["Database", settings.storage.database],
                  ["Vector store", settings.storage.vectors],
                  ["Uploads", settings.storage.uploads],
                  ["Reports", settings.storage.reports],
                ] as const
              ).map(([label, value]) => (
                <div
                  key={label}
                  className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 py-2.5 last:border-0"
                >
                  <span className="text-sm text-slate-400">{label}</span>
                  <span className="truncate font-mono text-xs text-slate-300">
                    {value}
                  </span>
                </div>
              ))}
            </div>
          </SettingsCard>

          <SettingsCard icon={Info} title="About">
            <p className="text-slate-300">
              ANVESHAK (AI Memory Forensic Investigation Assistant) is a local
              AI-powered platform for analyzing memory dumps, correlating
              evidence, and generating investigation reports.
            </p>

            <p className="mt-3 text-xs text-slate-500">
              All analysis runs locally. No investigation data leaves this
              machine. Live service health is shown in the header.
            </p>
          </SettingsCard>
        </>
      ) : null}
    </div>
  );
}
