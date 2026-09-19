import { describe, expect, it, vi } from "vitest";
import { readOnlyMiddleware, restrictClientCapabilities } from "./readonly";
describe("read-only client capabilities", () => {
  it("retains diagnostics while removing write and action capabilities", () => {
    const capabilities = {
      workspace: {
        applyEdit: true,
        workspaceEdit: { documentChanges: true },
        executeCommand: { dynamicRegistration: true },
      },
      textDocument: {
        diagnostic: { dynamicRegistration: false },
        publishDiagnostics: { relatedInformation: true },
        synchronization: { dynamicRegistration: true },
        completion: { dynamicRegistration: true },
        codeAction: { dynamicRegistration: true },
        formatting: { dynamicRegistration: true },
        rename: { dynamicRegistration: true },
      },
      window: { showDocument: { support: true }, workDoneProgress: true },
    };
    restrictClientCapabilities(capabilities);
    expect(capabilities.workspace).toEqual({ applyEdit: false });
    expect(capabilities.textDocument).toEqual({
      diagnostic: { dynamicRegistration: false },
    });
    expect(capabilities.window).toEqual({ showDocument: { support: false } });
  });
  it("denies edits, external document opens, and dynamic registrations without calling the client", async () => {
    const next = vi.fn();
    const applied = await readOnlyMiddleware.workspace!.handleApplyEdit!(
      {} as never,
      next as never,
    );
    expect(applied).toEqual({
      applied: false,
      failureReason: "Open Trestle diagnostics are read-only.",
    });
    const shown = await readOnlyMiddleware.window!.showDocument!(
      {} as never,
      undefined as never,
      next as never,
    );
    expect(shown).toEqual({ success: false });
    await readOnlyMiddleware.handleRegisterCapability!(
      {} as never,
      next as never,
    );
    readOnlyMiddleware.handleDiagnostics!(
      {} as never,
      [] as never,
      next as never,
    );
    expect(next).not.toHaveBeenCalled();
  });
});
