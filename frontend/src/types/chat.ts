export interface EvidenceReference {
  index: number;
  evidence_id: number | null;
  plugin_name: string | null;
  artifact_type: string | null;
  confidence_score: number | null;
  document: string;
  score: number | null;
}

export interface ChatQueryResponse {
  investigation_id: string;
  session_id?: string | null;
  question: string;
  answer: string;
  confidence: number;
  insufficient: boolean;
  citations: EvidenceReference[];
  references: EvidenceReference[];
}

export interface ChatHistoryMessage {
  id: number;
  role: string;
  content: string;
  citations: EvidenceReference[] | null;
  confidence: number | null;
  created_at: string;
}

export interface ChatHistoryResponse {
  investigation_id: string;
  session_id?: string | null;
  messages: ChatHistoryMessage[];
}
