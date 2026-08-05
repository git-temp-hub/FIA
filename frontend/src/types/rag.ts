export interface RAGSearchItem {
  evidence_id: number | null;
  investigation_id: string | null;
  plugin_name: string | null;
  artifact_type: string | null;
  confidence_score: number | null;
  document: string;
  distance: number | null;
  score: number | null;
}

export interface RAGSearchResponse {
  query: string;
  items: RAGSearchItem[];
  count: number;
}

export interface RAGIndexResponse {
  investigation_id: string;
  status: string;
  indexed: number;
  total: number;
  removed: number;
}
