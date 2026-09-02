export interface AnalysisSettings {
  plugins: string[];
  plugin_timeout_seconds: number;
  max_concurrency: number;
}

export interface UploadSettings {
  max_dump_size_gb: number;
}

export interface LLMSettings {
  model: string;
  base_url: string;
}

export interface StoragePaths {
  database: string;
  vectors: string;
  uploads: string;
  reports: string;
}

export interface PlatformSettings {
  analysis: AnalysisSettings;
  upload: UploadSettings;
  llm: LLMSettings;
  storage: StoragePaths;
  available_plugins: string[];
  /** Settings currently overridden by an environment variable. */
  env_shadowed: string[];
}

export interface SettingsUpdate {
  analysis?: AnalysisSettings;
  upload?: UploadSettings;
  llm?: LLMSettings;
}
