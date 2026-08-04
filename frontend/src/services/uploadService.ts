import api from "./api";

import type { UploadResponse } from "../types/upload";

export async function uploadMemoryDump(
  file: File,
  onProgress?: (progress: number) => void,
): Promise<UploadResponse> {

  const formData = new FormData();

  formData.append("file", file);

  const response = await api.post<UploadResponse>(
    "/upload/",
    formData,
    {
      headers: {
        "Content-Type": "multipart/form-data",
      },

      onUploadProgress(progressEvent) {

        if (!onProgress) return;

        if (!progressEvent.total) return;

        const progress = Math.round(
          (progressEvent.loaded * 100) /
          progressEvent.total,
        );

        onProgress(progress);

      },
    },
  );

  return response.data;

}