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
    <div className="flex items-center justify-center min-h-screen bg-canvas">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-8 bg-surface rounded-lg border border-border shadow-lg"
      >
        <h1 className="text-2xl font-bold mb-6 text-center">Sign In</h1>
        {error && (
          <div className="mb-4 p-3 bg-red-50 text-red-700 rounded text-sm">{error}</div>
        )}
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded bg-canvas"
            required
            autoFocus
          />
        </div>
        <div className="mb-6">
          <label className="block text-sm font-medium mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded bg-canvas"
            required
          />
        </div>
        <button
          type="submit"
          className="w-full py-2 px-4 bg-primary text-white rounded font-medium hover:opacity-90"
        >
          Sign In
        </button>
        <p className="mt-4 text-center text-sm text-muted">
          No account?{" "}
          <Link to="/ui/register" className="text-primary underline">
            Register
          </Link>
        </p>
      </form>
    </div>
  );
}
