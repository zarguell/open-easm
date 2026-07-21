import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "./client";
import type { PaginatedResponse } from "../lib/types";

export interface Finding {
  id: string
  org_id: string
  target_id: string
  rule_id: string
  risk: string
  headline: string
  description: string | null
  entity_ids: string[]
  evidence: Record<string, unknown>
  status: string
  confidence_level?: string
  confidence_score?: number
  first_seen_at: string | null
  last_seen_at: string | null
  created_at: string | null
}

export interface FindingsResponse {
  findings: Finding[]
  total: number
}

export interface FindingsParams {
  target_id?: string
  risk?: string
  status?: string
  rule_id?: string
  q?: string
  limit?: number
  offset?: number
}

export function useFindings(params: FindingsParams) {
  return useQuery({
    queryKey: ["findings", params],
    queryFn: async () => {
      const searchParams: Record<string, string> = {};
      if (params.target_id) searchParams.target_id = params.target_id;
      if (params.risk) searchParams.risk = params.risk;
      if (params.status) searchParams.status = params.status;
      if (params.rule_id) searchParams.rule_id = params.rule_id;
      if (params.q) searchParams.q = params.q;
      if (params.limit) searchParams.limit = String(params.limit);
      if (params.offset) searchParams.offset = String(params.offset);
      const resp = await api.get("findings", { searchParams }).json<PaginatedResponse<Finding>>();
      return { findings: resp.items, total: resp.total };
    },
    placeholderData: (prev) => prev,
  });
}

export function usePatchFindingStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) =>
      api.patch(`findings/${id}`, { json: { status } }).json<Finding>(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}

export async function patchFindingStatus(id: string, status: string): Promise<Finding> {
  return api.patch(`findings/${id}`, { json: { status } }).json<Finding>();
}

export async function getFinding(id: string): Promise<Finding> {
  return api.get(`findings/${id}`).json<Finding>();
}

export async function listFindingRules(): Promise<string[]> {
  const data = await api.get("findings/rules").json<{ rules: string[] }>();
  return data.rules;
}
