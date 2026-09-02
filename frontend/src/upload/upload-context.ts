import { createContext, useContext } from "react";

export interface ActiveUpload {
  filename: string;
  size: number;
  progress: number;
  /** Populated when the upload finishes successfully. */
  investigationId: string | null;
  error: string | null;
  done: boolean;
}

export interface UploadContextValue {
  upload: ActiveUpload | null;
  /** True while bytes are still transferring. */
  uploading: boolean;
  startUpload: (file: File) => Promise<string | null>;
  clearUpload: () => void;
}

export const UploadContext = createContext<UploadContextValue | null>(null);

export function useUpload(): UploadContextValue {
  const context = useContext(UploadContext);

  if (!context) {
    throw new Error("useUpload must be used within an UploadProvider");
  }

  return context;
}
