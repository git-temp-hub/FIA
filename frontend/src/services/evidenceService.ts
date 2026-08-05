import api from "./api";

import type {
  EvidenceDetail,
  EvidenceFilters,
  EvidenceInvestigationSummary,
  EvidenceListResponse,
} from "../types/evidence";

export async function listEvidence(
  filters: Partial<EvidenceFilters>,
): Promise<EvidenceListResponse> {
  const params: Record<string, string | number | undefined> = {
    investigation_id: filters.investigation_id || undefined,
    plugin: filters.plugin || undefined,
    artifact_type: filters.artifact_type || undefined,
    severity: filters.severity || undefined,
    search: filters.search || undefined,
    sort_by: filters.sort_by || "id",
    sort_order: filters.sort_order || "desc",
    page: filters.page || 1,
    page_size: filters.page_size || 20,
  };

  const response = await api.get<EvidenceListResponse>("/evidence/", {
    params,
  });

  return response.data;
}

export async function getEvidenceDetail(
  evidenceId: number,
): Promise<EvidenceDetail> {
  const response = await api.get<EvidenceDetail>(
    `/evidence/${evidenceId}`,
  );

  return response.data;
}

export async function listEvidenceInvestigations(): Promise<
  EvidenceInvestigationSummary[]
> {
  const response = await api.get<{
    items: EvidenceInvestigationSummary[];
  }>("/evidence/investigations");

  return response.data.items;
}
