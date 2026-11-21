import type { RunStatus, RuntimeComponentState, TaskStatus } from "./types";

export type StatusValue =
  | RunStatus
  | RuntimeComponentState
  | TaskStatus
  | "incomplete"
  | "passed"
  | "unavailable";

type StatusMark =
  | "active"
  | "available"
  | "failed"
  | "incomplete"
  | "leased"
  | "passed"
  | "pending"
  | "starting"
  | "unavailable";

type StatusGlyph = { mark: StatusMark; glyph: string };

const statusGlyphs = {
  active: { mark: "active", glyph: "●" },
  available: { mark: "available", glyph: "◇" },
  canceled: { mark: "unavailable", glyph: "−" },
  failed: { mark: "failed", glyph: "×" },
  incomplete: { mark: "incomplete", glyph: "!" },
  leased: { mark: "leased", glyph: "◆" },
  passed: { mark: "passed", glyph: "✓" },
  pending: { mark: "pending", glyph: "○" },
  ready: { mark: "passed", glyph: "✓" },
  skipped: { mark: "unavailable", glyph: "−" },
  starting: { mark: "starting", glyph: "◔" },
  succeeded: { mark: "passed", glyph: "✓" },
  unavailable: { mark: "unavailable", glyph: "−" },
} satisfies Record<StatusValue, StatusGlyph>;

export function StatusIcon({ value }: { value: StatusValue }) {
  const { mark, glyph } = statusGlyphs[value];
  return (
    <span className="status-icon" data-status-icon={mark} aria-hidden="true">
      {glyph}
    </span>
  );
}

export function InstrumentIcon() {
  return <span className="instrument-icon" aria-hidden="true" />;
}
