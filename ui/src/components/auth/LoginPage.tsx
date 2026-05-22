import { useState, type FormEvent } from "react";
import { useNavigate, Link } from "react-router";
import { useAuth } from "../../hooks/useAuth";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await login(username, password);
      navigate("/ui");
    } catch {
      setError("Invalid username or password");
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-canvas px-4">
      <form
        onSubmit={handleSubmit}
        className="flex flex-col gap-5 w-full max-w-[28rem] p-8 bg-canvas-elevated rounded-xl border border-hairline shadow-lg"
      >
        <h1 className="text-2xl font-bold text-center text-ink">Sign In</h1>
        {error && (
          <div className="p-3 bg-status-error/10 text-status-error rounded-md text-sm border border-status-error/20">{error}</div>
        )}
        <div className="flex flex-col gap-1.5">
          <label className="block text-sm font-medium text-body">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter your username"
            className="w-full px-3 py-2.5 border border-hairline-soft rounded-md bg-canvas-soft text-ink placeholder:text-mute/50 focus:outline-none focus:border-primary focus:ring-1 focus:ring-ring-focus"
            required
            autoFocus
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <label className="block text-sm font-medium text-body">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            className="w-full px-3 py-2.5 border border-hairline-soft rounded-md bg-canvas-soft text-ink placeholder:text-mute/50 focus:outline-none focus:border-primary focus:ring-1 focus:ring-ring-focus"
            required
          />
        </div>
        <button
          type="submit"
          className="w-full py-2.5 px-4 bg-primary text-on-primary rounded-md font-semibold hover:opacity-90 transition-opacity"
        >
          Sign In
        </button>
        <p className="text-center text-sm text-mute">
          No account?{" "}
          <Link to="/ui/register" className="text-primary hover:text-primary-soft underline transition-colors">
            Register
          </Link>
        </p>
      </form>
    </div>
  );
}
