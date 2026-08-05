export interface ReportInfo {
  id: number;
  investigation_id: string;
  case_name: string;
  dump_filename: string | null;
  sha256_hash: string | null;
  filename: string;
  file_size: number;
  status: string;
  error_message: string | null;
  generated_at: string;
}

export interface ReportListResponse {
  items: ReportInfo[];
}

export interface ReportGenerateResponse extends ReportInfo {
  message: string;
}

export interface ReportDetailResponse extends ReportInfo {
  memory_dump_filename: string | null;
  investigation_status: string | null;
  total_plugins: number;
  successful_plugins: number;
  failed_plugins: number;
  total_evidence: number;
  investigation_duration: number;
}
