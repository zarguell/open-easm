import { useState, type FormEvent } from "react";
import { useNavigate, Link } from "react-router";
import { authApi } from "../../api/auth";

export function RegisterPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    try {
      await authApi.register({ username, password });
      navigate("/ui/login");
    } catch (err: any) {
      if (err?.response?.status === 409) {
        setError("Username already taken");
      } else if (err?.response?.status === 403) {
        setError("Registration is closed. Contact an administrator.");
      } else {
        setError("Registration failed. Please try again.");
      }
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-canvas px-4">
      <form
        onSubmit={handleSubmit}
        className="flex flex-col gap-5 w-full max-w-[28rem] p-8 bg-canvas-elevated rounded-xl border border-hairline shadow-lg"
      >
        <h1 className="text-2xl font-bold text-center text-ink">Create Account</h1>
        {error && (
          <div className="p-3 bg-status-error/10 text-status-error rounded-md text-sm border border-status-error/20">{error}</div>
        )}
        <div className="flex flex-col gap-1.5">
          <label className="block text-sm font-medium text-body">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Choose a username"
            className="w-full px-3 py-2.5 border border-hairline-soft rounded-md bg-canvas-soft text-ink placeholder:text-mute/50 focus:outline-none focus:border-primary focus:ring-1 focus:ring-ring-focus"
            required
            minLength={3}
            autoFocus
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <label className="block text-sm font-medium text-body">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Create a password (min 8 chars)"
            className="w-full px-3 py-2.5 border border-hairline-soft rounded-md bg-canvas-soft text-ink placeholder:text-mute/50 focus:outline-none focus:border-primary focus:ring-1 focus:ring-ring-focus"
            required
            minLength={8}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <label className="block text-sm font-medium text-body">Confirm Password</label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="Confirm your password"
            className="w-full px-3 py-2.5 border border-hairline-soft rounded-md bg-canvas-soft text-ink placeholder:text-mute/50 focus:outline-none focus:border-primary focus:ring-1 focus:ring-ring-focus"
            required
            minLength={8}
          />
        </div>
        <button
          type="submit"
          className="w-full py-2.5 px-4 bg-primary text-on-primary rounded-md font-semibold hover:opacity-90 transition-opacity"
        >
          Create Account
        </button>
        <p className="text-center text-sm text-mute">
          Already have an account?{" "}
          <Link to="/ui/login" className="text-primary hover:text-primary-soft underline transition-colors">
            Sign In
          </Link>
        </p>
      </form>
    </div>
  );
}
