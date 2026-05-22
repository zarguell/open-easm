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
        className="flex flex-col gap-4 w-full max-w-md p-8 bg-canvas-elevated rounded-lg border border-hairline shadow-lg"
      >
        <h1 className="text-2xl font-bold text-center">Sign In</h1>
        {error && (
          <div className="p-3 bg-red-50 text-red-700 rounded text-sm">{error}</div>
        )}
        <div className="flex flex-col gap-1">
          <label className="block text-sm font-medium">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 border border-hairline rounded bg-canvas"
            required
            autoFocus
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className="block text-sm font-medium">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border border-hairline rounded bg-canvas"
            required
          />
        </div>
        <button
          type="submit"
          className="w-full py-2 px-4 bg-primary text-white rounded font-medium hover:opacity-90"
        >
          Sign In
        </button>
        <p className="text-center text-sm text-mute">
          No account?{" "}
          <Link to="/ui/register" className="text-primary underline">
            Register
          </Link>
        </p>
      </form>
    </div>
  );
}
