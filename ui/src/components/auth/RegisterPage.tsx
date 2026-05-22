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
        className="w-full max-w-md p-8 bg-canvas-elevated rounded-lg border border-hairline shadow-lg"
      >
        <h1 className="text-2xl font-bold mb-6 text-center">Create Account</h1>
        {error && (
          <div className="mb-4 p-3 bg-red-50 text-red-700 rounded text-sm">{error}</div>
        )}
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 border border-hairline rounded bg-canvas"
            required
            minLength={3}
            autoFocus
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border border-hairline rounded bg-canvas"
            required
            minLength={8}
          />
        </div>
        <div className="mb-6">
          <label className="block text-sm font-medium mb-1">Confirm Password</label>
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="w-full px-3 py-2 border border-hairline rounded bg-canvas"
            required
            minLength={8}
          />
        </div>
        <button
          type="submit"
          className="w-full py-2 px-4 bg-primary text-white rounded font-medium hover:opacity-90"
        >
          Create Account
        </button>
        <p className="mt-4 text-center text-sm text-mute">
          Already have an account?{" "}
          <Link to="/ui/login" className="text-primary underline">
            Sign In
          </Link>
        </p>
      </form>
    </div>
  );
}
