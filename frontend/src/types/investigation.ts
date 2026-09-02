export interface InvestigationSummary {
  investigation_id: string;
  filename: string;
  status: string;
  progress: number;
  uploaded_at: string | null;
  evidence_count: number;
  plugin_count: number;
}

export interface InvestigationListResponse {
  items: InvestigationSummary[];
  total: number;
}
