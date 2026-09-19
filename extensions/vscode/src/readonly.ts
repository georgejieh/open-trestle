import type { LanguageClientOptions } from "vscode-languageclient/node";
import type { ClientCapabilities } from "vscode-languageserver-protocol";
export function restrictClientCapabilities(
  capabilities: ClientCapabilities,
): void {
  const diagnostic = capabilities.textDocument?.diagnostic;
  capabilities.workspace = { applyEdit: false };
  capabilities.textDocument = {};
  if (diagnostic !== undefined)
    capabilities.textDocument.diagnostic = diagnostic;
  capabilities.window = { showDocument: { support: false } };
}

export const readOnlyMiddleware: NonNullable<
  LanguageClientOptions["middleware"]
> = {
  handleDiagnostics: () => {},
  didOpen: async () => {},
  didChange: async () => {},
  willSave: async () => {},
  willSaveWaitUntil: async () => [],
  didSave: async () => {},
  didClose: async () => {},
  handleRegisterCapability: async () => {},
  handleUnregisterCapability: async () => {},
  workspace: {
    handleApplyEdit: () => ({
      applied: false,
      failureReason: "Open Trestle diagnostics are read-only.",
    }),
    configuration: (params) => params.items.map(() => null),
    didChangeConfiguration: async () => {},
    didChangeWatchedFile: async () => {},
    didChangeWorkspaceFolders: async () => {},
    didCreateFiles: async () => {},
    willCreateFiles: async () => null,
    didRenameFiles: async () => {},
    willRenameFiles: async () => null,
    didDeleteFiles: async () => {},
    willDeleteFiles: async () => null,
  },
  window: { showDocument: async () => ({ success: false }) },
  provideCompletionItem: () => [],
  provideCodeActions: () => [],
  provideCodeLenses: () => [],
  provideDocumentLinks: () => [],
  provideDocumentColors: () => [],
  provideColorPresentations: () => [],
  provideInlayHints: () => [],
  provideInlineCompletionItems: () => [],
  provideLinkedEditingRange: () => null,
  provideDocumentFormattingEdits: () => [],
  provideDocumentRangeFormattingEdits: () => [],
  provideDocumentRangesFormattingEdits: () => [],
  provideOnTypeFormattingEdits: () => [],
  provideRenameEdits: () => null,
  prepareRename: () => null,
  executeCommand: () => undefined,
};
