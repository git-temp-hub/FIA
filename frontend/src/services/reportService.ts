import api from "./api";

import type {
  ReportDetailResponse,
  ReportGenerateResponse,
  ReportListResponse,
} from "../types/report";

export async function listReports(): Promise<ReportListResponse> {
  const response = await api.get<ReportListResponse>("/reports");
  return response.data;
}

export async function generateReport(
  investigationId: string,
): Promise<ReportGenerateResponse> {
  const response = await api.post<ReportGenerateResponse>(
    `/reports/generate/${encodeURIComponent(investigationId)}`,
  );
  return response.data;
}

export async function getReportDetail(
  reportId: number,
): Promise<ReportDetailResponse> {
  const response = await api.get<ReportDetailResponse>(
    `/reports/${reportId}`,
  );
  return response.data;
}

export async function downloadReport(reportId: number): Promise<void> {
  const response = await api.get(`/reports/download/${reportId}`, {
    responseType: "blob",
  });

  const disposition = response.headers["content-disposition"] as
    | string
    | undefined;

  const match = disposition?.match(/filename="?([^"]+)"?/);
  const filename = match?.[1] ?? `report_${reportId}.pdf`;

  const url = window.URL.createObjectURL(
    new Blob([response.data as BlobPart], {
      type: "application/pdf",
    }),
  );

  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  window.URL.revokeObjectURL(url);
}
