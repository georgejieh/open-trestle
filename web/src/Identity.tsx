import { useEffect, useRef, useState } from "react";

export function shortIdentity(value: string) {
  return value ? `${value.slice(0, 10)}…${value.slice(-8)}` : "Not available";
}

export function Identity({ label, value }: { label: string; value: string }) {
  const [copyStatus, setCopyStatus] = useState<"copied" | "failed" | "">("");
  const attempt = useRef(0);
  const clearTimer = useRef<number | undefined>(undefined);
  const copyStatusValue = useRef(value);
  useEffect(() => {
    if (copyStatusValue.current !== value) setCopyStatus("");
    return () => {
      attempt.current++;
      window.clearTimeout(clearTimer.current);
      clearTimer.current = undefined;
    };
  }, [value]);
  async function copy() {
    if (!value) return;
    const currentAttempt = ++attempt.current;
    let status: "copied" | "failed" = "failed";
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(value);
        status = "copied";
      }
    } catch {}
    if (currentAttempt !== attempt.current) return;
    window.clearTimeout(clearTimer.current);
    copyStatusValue.current = value;
    setCopyStatus(status);
    clearTimer.current = window.setTimeout(() => {
      if (currentAttempt === attempt.current) {
        setCopyStatus("");
        clearTimer.current = undefined;
      }
    }, 1500);
  }
  return (
    <div className="identity-row">
      <div>
        <dt>{label}</dt>
        <dd title={value || undefined}>
          {value ? (
            <>
              <span aria-hidden="true">{shortIdentity(value)}</span>
              <span className="sr-only">{value}</span>
            </>
          ) : (
            "Not available"
          )}
        </dd>
      </div>
      {value && (
        <button
          className="icon-button"
          type="button"
          onClick={copy}
          aria-label={`Copy ${label}: ${value}`}
        >
          <span aria-hidden="true">Copy</span>
          {copyStatus && copyStatusValue.current === value && (
            <span className="copy-note" role="status">
              {copyStatus === "copied" ? "Copied" : "Copy failed"}
            </span>
          )}
        </button>
      )}
    </div>
  );
}
