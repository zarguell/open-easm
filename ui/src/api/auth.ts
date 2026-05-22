import api from "./client";

export interface User {
  id: string;
  username: string;
  display_name: string | null;
  email: string | null;
  role: string;
  org_id: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  password: string;
  email?: string;
  display_name?: string;
}

export interface CreateApiKeyRequest {
  name: string;
  expires_in_days?: number;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface ApiKeyWithSecret extends ApiKey {
  key: string;
}

export const authApi = {
  login: (data: LoginRequest) =>
    api.post("auth/login", { json: data }).json<User>(),

  logout: () => api.post("auth/logout"),

  register: (data: RegisterRequest) =>
    api.post("auth/register", { json: data }).json<User>(),

  me: () => api.get("auth/me").json<User>(),

  listApiKeys: () => api.get("auth/api-keys").json<ApiKey[]>(),

  createApiKey: (data: CreateApiKeyRequest) =>
    api.post("auth/api-keys", { json: data }).json<ApiKeyWithSecret>(),

  deleteApiKey: (id: string) => api.delete(`auth/api-keys/${id}`),
};
