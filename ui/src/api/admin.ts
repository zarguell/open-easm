import api from './client'

export interface User {
  id: string
  username: string
  email: string | null
  display_name: string | null
  role: string
  created_at: string
}

export const listUsers = () => api.get('auth/users').json<User[]>()

export const deleteUser = (userId: string) => api.delete(`auth/users/${userId}`)

export const updateUser = (userId: string, data: Record<string, unknown>) =>
  api.put(`auth/users/${userId}`, { json: data })

export async function registerUser(username: string, password: string): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await api.post('auth/register', { json: { username, password } })
    if (res.ok) return { ok: true }
    const body = await res.json<{ error: string }>()
    return { ok: false, error: body.error }
  } catch {
    return { ok: false, error: 'registration_failed' }
  }
}
