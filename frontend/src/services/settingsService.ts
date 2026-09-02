import api from "./api";
import type { PlatformSettings, SettingsUpdate } from "../types/settings";

export async function getPlatformSettings(): Promise<PlatformSettings> {
  const response = await api.get<PlatformSettings>("/settings");

  return response.data;
}

export async function updatePlatformSettings(
  update: SettingsUpdate,
): Promise<PlatformSettings> {
  const response = await api.put<PlatformSettings>("/settings", update);

  return response.data;
}
