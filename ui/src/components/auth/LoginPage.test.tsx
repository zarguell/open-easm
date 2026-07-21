import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { LoginPage } from "./LoginPage";

vi.mock("../../hooks/useAuth", () => ({
  useAuth: () => ({
    login: vi.fn(),
    user: null,
    loading: false,
    error: null,
  }),
}));

describe("LoginPage", () => {
  it("renders login form with all accessible labels", () => {
    render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    );

    expect(screen.getByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/enter your username/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/enter your password/i)).toBeInTheDocument();
  });
});
