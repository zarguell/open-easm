import { describe, it, expect } from "vitest";

describe("GeoMap popup content", () => {
  it("should escape HTML in entity values", () => {
    const malicious = "<img src=x onerror=alert(1)>";
    const el = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = malicious;
    el.appendChild(strong);

    expect(el.innerHTML).toBe("<strong>&lt;img src=x onerror=alert(1)&gt;</strong>");
    expect(el.textContent).toBe(malicious);
  });
});
