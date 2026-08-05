import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000",
});

export function getErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail;

    if (typeof detail === "string" && detail.trim()) {
      return detail;
    }

    if (error.code === "ERR_NETWORK") {
      return "Cannot reach the backend server. Please check that it is running.";
    }

    if (error.response) {
      return `Request failed with status ${error.response.status}.`;
    }
  }

  return "An unexpected error occurred.";
}

export default api;
