export interface UploadResponse {

  status: string;

  investigation_id: string;

  filename: string;

  size: number;

  sha256: string;

  stored_path: string;

}

export interface UploadState {

  uploading: boolean;

  progress: number;

  error: string | null;

  completed: boolean;

}