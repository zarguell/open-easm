import { useState, useEffect, useCallback, type FormEvent } from 'react'
import { useAuth } from '../../hooks/useAuth'
import { listUsers, deleteUser, registerUser, updateUser, type User } from '../../api/admin'

export function UsersView() {
  const { user: currentUser } = useAuth()
  const [users, setUsers] = useState<User[]>([])
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // create user form
  const [showCreate, setShowCreate] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')

  // change password form
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')

  const load = useCallback(async () => {
    try {
      setUsers(await listUsers())
    } catch {
      setError('Failed to load users')
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleDelete = async (u: User) => {
    if (!confirm(`Delete user "${u.username}"?`)) return
    try {
      await deleteUser(u.id)
      setUsers(prev => prev.filter(x => x.id !== u.id))
      setSuccess(`Deleted user "${u.username}"`)
    } catch {
      setError('Failed to delete user')
    }
  }

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    const result = await registerUser(newUsername, newPassword)
    if (result.ok) {
      setShowCreate(false)
      setNewUsername('')
      setNewPassword('')
      await load()
      setSuccess(`Created user "${newUsername}"`)
    } else {
      const msg = result.error === 'registration_requires_admin' ? 'Registration requires admin privileges' :
                  result.error === 'username_taken' ? 'Username already taken' :
                  'Registration failed'
      setError(msg)
    }
  }

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    if (newPw !== confirmPw) {
      setError('Passwords do not match')
      return
    }
    try {
      await updateUser(currentUser!.id, {
        current_password: currentPw,
        new_password: newPw,
      })
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
      setSuccess('Password changed')
    } catch {
      setError('Failed to change password. Check your current password.')
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold text-ink">User Management</h1>

      {error && (
        <div className="p-3 bg-status-error/10 text-status-error rounded-md text-sm border border-status-error/20 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => { setError(''); }} className="text-status-error/60 hover:text-status-error ml-2">&times;</button>
        </div>
      )}
      {success && (
        <div className="p-3 bg-emerald-500/10 text-emerald-500 rounded-md text-sm border border-emerald-500/20 flex items-center justify-between">
          <span>{success}</span>
          <button onClick={() => { setSuccess(''); }} className="text-emerald-500/60 hover:text-emerald-500 ml-2">&times;</button>
        </div>
      )}

      {/* My Profile */}
      <section>
        <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">My Profile</span>
        <div className="mt-2 flex flex-wrap gap-4">
          <div className="bg-canvas-elevated rounded-xl border border-hairline p-5 flex-1 min-w-[280px]">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-primary/10 text-primary flex items-center justify-center font-semibold text-lg">
                {currentUser?.username?.charAt(0).toUpperCase()}
              </div>
              <div>
                <p className="text-ink font-medium">{currentUser?.username}</p>
                <p className="text-mute text-xs">{currentUser?.email ?? 'No email set'}</p>
              </div>
              <span className="ml-auto inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary">
                {currentUser?.role}
              </span>
            </div>

            <form onSubmit={handleChangePassword} className="space-y-3">
              <input
                type="password"
                value={currentPw}
                onChange={e => { setCurrentPw(e.target.value); }}
                placeholder="Current password"
                className="w-full h-10 rounded-sm border border-hairline bg-canvas-soft px-3 text-sm text-ink placeholder:text-mute/50 focus:outline-none focus:ring-1 focus:ring-primary"
                required
              />
              <input
                type="password"
                value={newPw}
                onChange={e => { setNewPw(e.target.value); }}
                placeholder="New password (min 8 chars)"
                className="w-full h-10 rounded-sm border border-hairline bg-canvas-soft px-3 text-sm text-ink placeholder:text-mute/50 focus:outline-none focus:ring-1 focus:ring-primary"
                required
                minLength={8}
              />
              <input
                type="password"
                value={confirmPw}
                onChange={e => { setConfirmPw(e.target.value); }}
                placeholder="Confirm new password"
                className="w-full h-10 rounded-sm border border-hairline bg-canvas-soft px-3 text-sm text-ink placeholder:text-mute/50 focus:outline-none focus:ring-1 focus:ring-primary"
                required
                minLength={8}
              />
              <button
                type="submit"
                className="h-10 px-4 bg-primary text-on-primary rounded-md font-semibold hover:opacity-90 transition-opacity text-sm"
              >
                Change Password
              </button>
            </form>
          </div>
        </div>
      </section>

      {/* All Users */}
      <section>
        <div className="flex items-center justify-between">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-mute">All Users</span>
          <button
            onClick={() => { setShowCreate(!showCreate); }}
            className="h-10 px-4 bg-primary text-on-primary rounded-md font-semibold hover:opacity-90 transition-opacity text-sm"
          >
            Create User
          </button>
        </div>

        {showCreate && (
          <form onSubmit={handleCreate} className="mt-3 mb-4 p-4 bg-canvas-elevated rounded-xl border border-hairline">
            <div className="flex flex-wrap gap-3">
              <input
                type="text"
                value={newUsername}
                onChange={e => { setNewUsername(e.target.value); }}
                placeholder="Username"
                required
                minLength={3}
                className="h-10 rounded-sm border border-hairline bg-canvas-soft px-3 text-sm text-ink placeholder:text-mute/50 focus:outline-none focus:ring-1 focus:ring-primary flex-1 min-w-[160px]"
              />
              <input
                type="password"
                value={newPassword}
                onChange={e => { setNewPassword(e.target.value); }}
                placeholder="Password (min 8 chars)"
                required
                minLength={8}
                className="h-10 rounded-sm border border-hairline bg-canvas-soft px-3 text-sm text-ink placeholder:text-mute/50 focus:outline-none focus:ring-1 focus:ring-primary flex-1 min-w-[160px]"
              />
              <button
                type="submit"
                className="h-10 px-4 bg-primary text-on-primary rounded-md font-semibold hover:opacity-90 transition-opacity text-sm"
              >
                Create
              </button>
              <button
                type="button"
                onClick={() => { setShowCreate(false); }}
                className="h-10 px-4 border border-hairline rounded-md text-body hover:bg-canvas-soft transition-colors text-sm"
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        <div className="mt-2 bg-canvas-elevated rounded-xl border border-hairline overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-hairline text-left text-mute text-xs uppercase tracking-wider">
                <th className="px-4 py-3 font-medium">Username</th>
                <th className="px-4 py-3 font-medium">Role</th>
                <th className="px-4 py-3 font-medium">Email</th>
                <th className="px-4 py-3 font-medium">Created</th>
                <th className="px-4 py-3 w-20"></th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} className="border-b border-hairline/50 hover:bg-canvas-soft/50 transition-colors">
                  <td className="px-4 py-3 text-ink font-medium">
                    {u.username}
                    {currentUser?.id === u.id && <span className="ml-2 text-[10px] text-mute uppercase tracking-wider">(you)</span>}
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary">
                      {u.role}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-mute">{u.email ?? '—'}</td>
                  <td className="px-4 py-3 text-mute">{new Date(u.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3 text-right">
                    {currentUser?.id !== u.id && (
                      <button
                        onClick={() => handleDelete(u)}
                        className="text-status-error hover:opacity-80 transition-opacity text-sm font-medium"
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {users.length === 0 && (
            <div className="p-8 text-center text-mute">No users found.</div>
          )}
        </div>
      </section>
    </div>
  )
}
