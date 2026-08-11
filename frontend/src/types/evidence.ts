export interface EvidenceItem {
  id: number;
  plugin: string;
  artifact_type: string;
  artifact_name: string;
  artifact_value: string;
  confidence_score: number;
  severity: string;
  classification_state?: string;
  risk_reasons?: string[];
  risk_indicators?: string[];
  created_at: string;
}

export interface EvidenceListResponse {
  items: EvidenceItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  plugins: string[];
  artifact_types: string[];
}

export interface EvidenceDetail extends EvidenceItem {
  plugin_execution_id: number;
  memory_dump_id: number | null;
  investigation_id: string | null;
}

export interface EvidenceInvestigationSummary {
  investigation_id: string;
  filename: string;
  status: string;
  progress: number;
  evidence_count: number;
  plugin_count: number;
}

export interface EvidenceFilters {
  investigation_id?: string;
  plugin?: string;
  artifact_type?: string;
  severity?: string;
  search?: string;
  sort_by: "id" | "artifact_type" | "artifact_name" | "created_at";
  sort_order: "asc" | "desc";
  page: number;
  page_size: number;
}
