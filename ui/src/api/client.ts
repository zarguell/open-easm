import ky from "ky";

const api = ky.create({
  prefix: "/api",
  headers: { Accept: "application/json" },
  timeout: 30_000,
  hooks: {
    afterResponse: [
      (request, _options, response) => {
        if (response.status === 401) {
          // Don't redirect on auth endpoint 401s (wrong password, etc.)
          const url = new URL(request.url);
          if (url.pathname.startsWith("/api/auth/")) {
            return;
          }
          const currentPath = window.location.pathname;
          if (!currentPath.startsWith("/ui/login") && !currentPath.startsWith("/ui/register")) {
            window.location.href = "/ui/login";
          }
        }
      },
    ],
  },
});

export default api;
