import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusIcon, type StatusValue } from "./Icons";

const expectedMarks: Record<StatusValue, string> = {
  active: "active",
  available: "available",
  blocked: "failed",
  canceled: "unavailable",
  failed: "failed",
  incomplete: "incomplete",
  leased: "leased",
  passed: "passed",
  pending: "pending",
  ready: "passed",
  skipped: "unavailable",
  starting: "starting",
  succeeded: "passed",
  unavailable: "unavailable",
};

describe("StatusIcon", () => {
  it("maps every runtime state without a fallback", () => {
    for (const [value, mark] of Object.entries(expectedMarks) as [
      StatusValue,
      string,
    ][]) {
      const { container, unmount } = render(<StatusIcon value={value} />);
      expect(container.firstElementChild).toHaveAttribute(
        "data-status-icon",
        mark,
      );
      unmount();
    }
  });

  it("gives transient states distinct visible marks", () => {
    const glyphs = ["active", "available", "leased", "pending", "starting"].map(
      (value) => {
        const { container, unmount } = render(
          <StatusIcon value={value as StatusValue} />,
        );
        const glyph = container.textContent;
        unmount();
        return glyph;
      },
    );
    expect(new Set(glyphs)).toHaveLength(glyphs.length);
    expect(glyphs.every(Boolean)).toBe(true);
  });
});
