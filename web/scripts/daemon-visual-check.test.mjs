import assert from "node:assert/strict";
import test from "node:test";
import { buildDaemonVisualReceipt } from "./daemon-visual-contract.mjs";

const digest = (value) => value.repeat(64);
const input = {
  phase: "before_restart",
  scope: { tenant: "tenant-a", repository: "repository-a", run: "local-alpha" },
  observed: {
    run_identity: digest("1"),
    diagnostic_set_identity: digest("2"),
    deterministic_check_identity: digest("3"),
    deterministic_check_state: "failed",
    observation_count: 1,
    observation_identities: [digest("4")],
  },
  metrics: {
    console_errors: 0,
    unexpected_egress: 0,
    horizontal_overflow: false,
    keyboard_focus_visible: true,
    evidence_disclosure_focus_visible: true,
    focus_order_steps: 3,
    reduced_motion: true,
    tap_targets_minimum: 44,
  },
  captures: ["overview", "findings", "runtime", "tablet", "mobile"].map(
    (view, index) => ({
      name: `${view}.png`,
      view,
      width: index === 4 ? 390 : 900,
      height: 844,
      bytes: 10,
      sha256: digest(String(index + 5)),
    }),
  ),
};

test("binds one visual receipt to an exact restart phase and review identities", () => {
  const receipt = buildDaemonVisualReceipt(input);
  assert.equal(receipt.phase, "before_restart");
  assert.equal(receipt.run_identity, digest("1"));
  assert.equal(receipt.diagnostic_set_identity, digest("2"));
  assert.equal(receipt.deterministic_check_identity, digest("3"));
  assert.equal(receipt.observation_count, 1);
});

test("rejects an unbound or unknown visual phase", () => {
  assert.throws(
    () => buildDaemonVisualReceipt({ ...input, phase: "" }),
    /phase/,
  );
  assert.throws(
    () =>
      buildDaemonVisualReceipt({
        ...input,
        observed: { ...input.observed, diagnostic_set_identity: "" },
      }),
    /identities/,
  );
});
