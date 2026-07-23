import { api, getToken } from "./api";
import type { AnalyticsSummary } from "./types";

export function getAnalyticsSummary(): Promise<AnalyticsSummary> {
  return api.get<AnalyticsSummary>("/api/analytics/summary", getToken() ?? undefined);
}
