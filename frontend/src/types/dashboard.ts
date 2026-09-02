export interface DashboardRecentInvestigation {
  investigation_id: string;
  filename: string;
  status: string;
  progress: number;
  uploaded_at: string;
  evidence_count: number;
}

export interface DashboardTrendPoint {
  day: string;
  label: string;
  investigations: number;
}

export interface DashboardEvidenceDistribution {
  artifact_type: string;
  count: number;
}

export interface DashboardSeverityDistribution {
  severity: string;
  count: number;
}

export interface SystemHealth {
  application: string;
  version: string;
  environment: string;
  database: string;
  ollama: string;
  chromadb: string;
}

export interface DashboardStats {
  total_investigations: number;
  total_memory_dumps: number;
  total_evidence: number;
  total_reports: number;
  total_ai_queries: number;
  plugin_executions_total: number;
  plugin_execution_success_rate: number;
  recent_investigations: DashboardRecentInvestigation[];
  investigation_trend: DashboardTrendPoint[];
  evidence_distribution: DashboardEvidenceDistribution[];
  severity_distribution: DashboardSeverityDistribution[];
  system_health: SystemHealth;
}
