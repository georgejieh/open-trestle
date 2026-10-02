import {
  Component,
  lazy,
  Suspense,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { ShieldCheck } from "./ShieldCheck";
import { InstrumentIcon, StatusIcon, type StatusValue } from "./Icons";
import { Identity } from "./Identity";
import {
  ApiError,
  fetchDiagnostics,
  fetchRun,
  fetchRuntimeStatus,
  validAccessToken,
  validScope,
} from "./api";
import type {
  Diagnostic,
  DiagnosticDeterministicCheck,
  DiagnosticSet,
  DeterministicObservation,
  RunReceipt,
  RunTask,
  RuntimeStatus,
  Scope,
} from "./types";
import "./styles.css";

type View = "overview" | "tasks" | "findings" | "runtime";
const emptyScope: Scope = { tenant: "", repository: "", run: "" };
function rememberedScope(): Scope {
  try {
    const value = JSON.parse(
      sessionStorage.getItem("open-trestle-scope") ?? "null",
    ) as unknown;
    if (typeof value === "object" && value !== null) {
      const scope = value as Scope;
      if (validScope(scope)) return scope;
    }
  } catch {}
  return emptyScope;
}
function Status({ value }: { value: StatusValue }) {
  return (
    <span className={`state state-${value}`}>
      <StatusIcon value={value} />
      <span>{value.replaceAll("_", " ")}</span>
    </span>
  );
}
function Locator({
  initial,
  onConnect,
  busy,
}: {
  initial: Scope;
  onConnect: (scope: Scope, token: string) => void;
  busy: boolean;
}) {
  const [scope, setScope] = useState(initial);
  const [token, setToken] = useState("");
  const [touched, setTouched] = useState({
    tenant: false,
    repository: false,
    run: false,
    token: false,
  });
  const identifierHint =
    "Use 1-128 lowercase letters or numbers; . _ : - are allowed. Start and end with a lowercase letter or number.";
  const tokenHint = "Use 32-512 non-space characters. Hidden and never saved.";
  const identifierValid = (value: string) =>
    validScope({ tenant: value, repository: value, run: value });
  const validity = {
    tenant: identifierValid(scope.tenant),
    repository: identifierValid(scope.repository),
    run: identifierValid(scope.run),
    token: validAccessToken(token),
  };
  const ready = Object.values(validity).every(Boolean);
  function submit(event: FormEvent) {
    event.preventDefault();
    if (ready) onConnect(scope, token);
  }
  function identifierField(key: keyof Scope, label: string, value: string) {
    const hintID = `locator-${key}-hint`;
    const errorID = `locator-${key}-error`;
    const hasError = touched[key] && !validity[key];
    return (
      <label>
        {label}
        <input
          value={value}
          aria-label={label}
          required
          maxLength={128}
          pattern="[a-z0-9](?:[a-z0-9._:\-]*[a-z0-9])?"
          aria-describedby={`${hintID}${hasError ? ` ${errorID}` : ""}`}
          aria-invalid={hasError || undefined}
          onChange={(event) =>
            setScope({ ...scope, [key]: event.target.value })
          }
          onBlur={() => setTouched((current) => ({ ...current, [key]: true }))}
          autoComplete="off"
          spellCheck={false}
        />
        <small className="field-hint" id={hintID}>
          {identifierHint}
        </small>
        {hasError && (
          <small className="field-error" id={errorID}>
            Use the listed identifier format.
          </small>
        )}
      </label>
    );
  }
  const tokenError = touched.token && !validity.token;
  return (
    <section className="locator" aria-labelledby="locator-title">
      <div className="locator-copy">
        <InstrumentIcon />
        <div>
          <h1 id="locator-title">Locate a review run</h1>
          <p>
            Connect to one exact tenant, repository, and run. Your access token
            stays in this tab and is never saved.
          </p>
        </div>
      </div>
      <form onSubmit={submit}>
        {identifierField("tenant", "Tenant", scope.tenant)}
        {identifierField("repository", "Repository", scope.repository)}
        {identifierField("run", "Run", scope.run)}
        <label className="token-field">
          Access token
          <span className="input-with-icon">
            <InstrumentIcon />
            <input
              type="password"
              name="open-trestle-access-token"
              value={token}
              aria-label="Access token"
              required
              minLength={32}
              maxLength={512}
              aria-describedby={`locator-token-hint${tokenError ? " locator-token-error" : ""}`}
              aria-invalid={tokenError || undefined}
              onChange={(event) => setToken(event.target.value)}
              onBlur={() =>
                setTouched((current) => ({ ...current, token: true }))
              }
              autoComplete="off"
              spellCheck={false}
            />
          </span>
          <small className="field-hint" id="locator-token-hint">
            {tokenHint}
          </small>
          {tokenError && (
            <small className="field-error" id="locator-token-error">
              Use 32-512 non-space characters.
            </small>
          )}
        </label>
        <p className="form-readiness" id="locator-readiness">
          {ready ? "Valid." : "Correct fields to connect."}
        </p>
        <button
          type="submit"
          className="primary-button"
          disabled={!ready || busy}
          aria-describedby="locator-readiness"
        >
          {busy ? <>Connecting</> : <>Connect to run</>}
        </button>
      </form>
    </section>
  );
}
function TaskSpine({
  tasks,
  selected,
  onSelect,
}: {
  tasks: RunTask[];
  selected: string;
  onSelect: (key: string) => void;
}) {
  return (
    <ol className="task-spine">
      {tasks.map((task, index) => (
        <li key={task.key} className={selected === task.key ? "selected" : ""}>
          <span className="depth-index" aria-hidden="true">
            {String(index + 1).padStart(2, "0")}
          </span>
          <button
            type="button"
            onClick={() => onSelect(task.key)}
            aria-current={selected === task.key ? "step" : undefined}
          >
            <span className="task-name">{task.key}</span>
            <span className="task-kind">{task.kind.replaceAll("_", " ")}</span>
            <Status value={task.status} />
          </button>
        </li>
      ))}
    </ol>
  );
}
function TaskInspector({ task }: { task: RunTask | undefined }) {
  if (!task)
    return (
      <div className="empty-inline">
        Select a task to inspect its durable state.
      </div>
    );
  return (
    <div className="inspector-content">
      <div className="inspector-heading">
        <InstrumentIcon />
        <div>
          <h2>{task.key}</h2>
          <p>{task.kind.replaceAll("_", " ")}</p>
        </div>
      </div>
      <dl>
        <div>
          <dt>Required</dt>
          <dd>{task.required ? "Yes" : "No"}</dd>
        </div>
        <div>
          <dt>Attempts</dt>
          <dd>
            {task.attempts} of {task.max_attempts}
          </dd>
        </div>
        <div>
          <dt>Failure</dt>
          <dd>{task.failure || "None"}</dd>
        </div>
        <Identity label="Task identity" value={task.task_identity} />
        <Identity label="Handler identity" value={task.handler_identity} />
        <Identity label="Input identity" value={task.input_identity} />
        <Identity label="Output identity" value={task.output_identity} />
      </dl>
    </div>
  );
}
function CheckOutcome({ check }: { check: DiagnosticDeterministicCheck }) {
  let label: string;
  let detail: string;
  switch (check.state) {
    case "passed":
      label = "Cleared gate";
      detail = "Cleared for this exact rule only.";
      break;
    case "failed":
      label = "Failed check";
      detail = "Exact matches require review.";
      break;
    case "incomplete":
      label = "Incomplete check";
      detail = "Human review is required.";
      break;
    case "not_applicable":
      label = "Abstention";
      detail = "No changed Go range was applicable. This rule was not cleared.";
      break;
  }
  return (
    <p
      className={`check-outcome${check.state === "failed" || check.state === "incomplete" ? " coverage-warning" : ""}`}
      data-state={check.state}
    >
      <strong>
        {label}: Static debug output {check.state.replaceAll("_", " ")}.
      </strong>{" "}
      {check.checked_ranges} of {check.applicable_ranges} changed Go ranges
      checked; {check.matches} exact matches. {detail}
    </p>
  );
}

function diagnosticItemCount(set: DiagnosticSet): number {
  return set.schema_version === 6
    ? set.observations.length
    : set.findings.length;
}

function diagnosticsRequireReview(set: DiagnosticSet): boolean {
  if (set.schema_version === 6)
    return set.observations.length > 0 || set.checks[0].state !== "passed";
  if (set.findings.length > 0) return true;
  if (set.schema_version === 1) return false;
  if (set.coverage.rejected_count > 0 || set.coverage.inconclusive_count > 0)
    return true;
  if (
    (set.schema_version === 3 ||
      set.schema_version === 4 ||
      set.schema_version === 5) &&
    set.source_coverage.omitted_count > 0
  )
    return true;
  return set.schema_version === 5 && set.checks[0].state !== "passed";
}

function primaryRunHeading(
  receipt: RunReceipt,
  diagnostics: DiagnosticSet | null,
  diagnosticNote: string,
  busy: boolean,
): string {
  if (receipt.status === "active") return "Execution in progress";
  if (receipt.status === "failed") return "Execution failed";
  if (receipt.status === "canceled") return "Execution canceled";
  if (busy && !diagnostics) return "Execution complete, loading review state";
  if (!diagnostics && diagnosticNote)
    return "Execution complete, review state unavailable";
  if (diagnostics && diagnosticsRequireReview(diagnostics))
    return "Execution complete, review required";
  return "Execution complete";
}

function CoverageLedger({ set }: { set: DiagnosticSet | null }) {
  if (!set) return null;
  if (set.schema_version === 6) {
    const check = set.checks[0];
    return (
      <section
        className="coverage-ledger"
        aria-labelledby="review-coverage-title"
      >
        <div>
          <h3 id="review-coverage-title">Deterministic rule coverage</h3>
          <p>Exact changed-range accounting for one local static rule.</p>
        </div>
        <ul className="coverage-facts" aria-label="Deterministic rule coverage">
          <li>{check.applicable_files} applicable files</li>
          <li>{check.applicable_ranges} applicable ranges</li>
          <li>{check.checked_ranges} checked ranges</li>
          <li>{check.matches} exact matches</li>
        </ul>
        <CheckOutcome check={check} />
        <ul className="coverage-conditions" aria-label="Coverage limits">
          <li>
            Observations are deterministic, not independently verified findings.
          </li>
          <li>
            Only changed Go ranges applicable to this exact rule were checked.
          </li>
          <li>
            A cleared rule does not approve the change or prove correctness.
          </li>
        </ul>
      </section>
    );
  }
  if (set.schema_version === 1) return null;
  const coverage = set.coverage;
  const sourceCoverage =
    set.schema_version === 3 ||
    set.schema_version === 4 ||
    set.schema_version === 5
      ? set.source_coverage
      : null;
  const omissionText =
    set.schema_version === 4 || set.schema_version === 5
      ? set.source_coverage.omissions
          .map(({ reason, count }) => `${count} ${reason.replaceAll("_", " ")}`)
          .join(", ")
      : "";
  const check = set.schema_version === 5 ? set.checks[0] : null;
  const incomplete =
    coverage.inconclusive_count > 0 || (sourceCoverage?.omitted_count ?? 0) > 0;
  return (
    <section
      className="coverage-ledger"
      aria-labelledby="review-coverage-title"
    >
      <div>
        <h3 id="review-coverage-title">Review coverage</h3>
        <p>Exact candidate outcomes and bounded source selection.</p>
      </div>
      <ul
        className="coverage-facts"
        aria-label={
          sourceCoverage
            ? "Candidate and source coverage"
            : "Candidate verification coverage"
        }
      >
        <li>{coverage.candidate_count} candidates</li>
        <li>{coverage.verified_count} verified</li>
        <li>{coverage.rejected_count} rejected</li>
        <li>{coverage.inconclusive_count} inconclusive</li>
        {sourceCoverage && (
          <>
            <li>{sourceCoverage.analyzed_count} sources analyzed</li>
            <li>{sourceCoverage.selected_count} selected for model review</li>
            <li>{sourceCoverage.omitted_count} omitted from model context</li>
          </>
        )}
      </ul>
      <ul
        className={`coverage-conditions${incomplete ? " coverage-warning" : ""}`}
        aria-label="Coverage conditions"
      >
        <li>
          {coverage.inconclusive_count > 0
            ? "Candidate coverage is incomplete: at least one verdict is inconclusive."
            : "Every admitted candidate received a terminal verdict."}
        </li>
        {sourceCoverage && (
          <li>
            {sourceCoverage.omitted_count > 0
              ? "Source coverage is incomplete: analyzed sources were omitted from model context."
              : "Every analyzed source was selected for model review."}
          </li>
        )}
        <li>Rejected candidates are not cleared gates.</li>
        <li>Source counts are not repository-wide.</li>
        <li>This does not approve the change or prove correctness.</li>
      </ul>
      {omissionText && <p>Omission reasons: {omissionText}.</p>}
      {check && <CheckOutcome check={check} />}
    </section>
  );
}

function Findings({ set }: { set: DiagnosticSet | null }) {
  if (!set)
    return (
      <section className="empty-state">
        <StatusIcon value="unavailable" />
        <h2>No verified finding set is available</h2>
        <p>
          The run may still be active, or it may have finished without a
          diagnostic artifact. Candidate model output is not shown here.
        </p>
      </section>
    );
  if (set.schema_version === 6) {
    if (set.observations.length === 0)
      return (
        <section className="empty-state">
          <StatusIcon
            value={set.checks[0].state === "passed" ? "passed" : "incomplete"}
          />
          <h2>No deterministic observations</h2>
          <p>
            This exact rule produced no source observation. Its coverage state
            remains visible above and does not approve the change.
          </p>
        </section>
      );
    return (
      <ol className="finding-list observation-list">
        {set.observations.map((observation) => (
          <Finding
            key={observation.identity}
            finding={observation}
            deterministic
          />
        ))}
      </ol>
    );
  }
  if (set.findings.length === 0) {
    const hasCandidateCoverage = (set.coverage?.candidate_count ?? 0) > 0;
    const gateRequiresReview =
      set.schema_version === 5 &&
      (set.checks[0].state === "failed" ||
        set.checks[0].state === "incomplete");
    const gateNotCleared =
      set.schema_version === 5 && set.checks[0].state !== "passed";
    const incomplete =
      (set.coverage?.inconclusive_count ?? 0) > 0 ||
      ((set.schema_version === 3 ||
        set.schema_version === 4 ||
        set.schema_version === 5) &&
        set.source_coverage.omitted_count > 0) ||
      gateRequiresReview;
    return (
      <section
        className={`empty-state${hasCandidateCoverage || incomplete || gateNotCleared ? "" : " verified"}`}
      >
        {incomplete || gateNotCleared ? (
          <StatusIcon value="incomplete" />
        ) : (
          <StatusIcon value="passed" />
        )}
        <h2>No verified findings</h2>
        <p>
          {incomplete
            ? gateRequiresReview
              ? "No candidate was promoted, but a deterministic check requires review. Human review is still required."
              : "No candidate was promoted, but review coverage remains incomplete. Human review is still required."
            : gateNotCleared
              ? "No candidate was promoted, and the deterministic check was not cleared. Human review is still required."
              : hasCandidateCoverage
                ? "No candidate was promoted. Rejected candidates are not cleared deterministic gates, and this does not approve the change."
                : "The diagnostic set is valid and contains zero promoted findings. This is not proof that the change is correct."}
        </p>
      </section>
    );
  }
  return (
    <ol className="finding-list">
      {set.findings.map((finding) => (
        <Finding key={finding.identity} finding={finding} />
      ))}
    </ol>
  );
}
function Finding({
  finding,
  deterministic = false,
}: {
  finding: Diagnostic | DeterministicObservation;
  deterministic?: boolean;
}) {
  return (
    <li className={`finding-row severity-edge-${finding.severity}`}>
      <div className={`severity severity-${finding.severity}`}>
        <StatusIcon
          value={finding.severity === "error" ? "failed" : "incomplete"}
        />
        <span>
          {finding.severity}
          {deterministic && " · deterministic"}
        </span>
      </div>
      <div className="finding-body">
        <h2>{finding.title}</h2>
        <p>{finding.message}</p>
        <div className="finding-meta">
          <span>
            {finding.path}:{finding.start_line}-{finding.end_line}
          </span>
          <span>
            {finding.evidence_ids.length} evidence{" "}
            {finding.evidence_ids.length === 1 ? "item" : "items"}
          </span>
        </div>
        <details className="finding-evidence">
          <summary>Inspect evidence</summary>
          <dl>
            <Identity
              label={
                deterministic ? "Observation identity" : "Diagnostic identity"
              }
              value={finding.identity}
            />
            {deterministic && "analysis_result_identity" in finding && (
              <>
                <Identity
                  label="Analysis result identity"
                  value={finding.analysis_result_identity}
                />
                <Identity
                  label="Deterministic check identity"
                  value={finding.check_identity}
                />
              </>
            )}
            {!deterministic && (
              <Identity
                label="Source finding identity"
                value={finding.source_identity}
              />
            )}
            <Identity
              label={
                deterministic
                  ? "Observation fingerprint"
                  : "Finding fingerprint"
              }
              value={finding.fingerprint}
            />
            {finding.evidence_ids.map((identity, index) => (
              <Identity
                key={identity}
                label={`Evidence reference ${index + 1}`}
                value={identity}
              />
            ))}
          </dl>
        </details>
      </div>
    </li>
  );
}
function RuntimeView({
  status,
  note,
}: {
  status: RuntimeStatus | null;
  note: string;
}) {
  if (!status)
    return (
      <section className="empty-state">
        <StatusIcon value="unavailable" />
        <h2>Runtime status is not available</h2>
        <p>{note || "This token may not have runtime inspection authority."}</p>
      </section>
    );
  const config = status.configuration;
  return (
    <div className="runtime-grid">
      <section className="run-summary">
        <div className="section-head">
          <div>
            <h2>Runtime state</h2>
            <p>Observed {new Date(status.observed_at).toLocaleString()}</p>
          </div>
          <Status value={status.ready ? "ready" : "starting"} />
        </div>
        <dl>
          <div>
            <dt>Metadata</dt>
            <dd>{config.metadata_backend}</dd>
          </div>
          <div>
            <dt>Artifacts</dt>
            <dd>
              {config.artifact_backend} ·{" "}
              {config.artifact_protection.replaceAll("_", " ")}
            </dd>
          </div>
          <div>
            <dt>Notifications</dt>
            <dd>{config.notification_backend.replaceAll("_", " ")}</dd>
          </div>
          <div>
            <dt>Rate limits</dt>
            <dd>{config.rate_limit_backend.replaceAll("_", " ")}</dd>
          </div>
          <div>
            <dt>Review mode</dt>
            <dd>{config.review_mode}</dd>
          </div>
          <div>
            <dt>Webhook ingress</dt>
            <dd>{config.webhook_ingress ? "Configured" : "Disabled"}</dd>
          </div>
          <div>
            <dt>Local workers</dt>
            <dd>{config.local_workers ? "Configured" : "Disabled"}</dd>
          </div>
          <div>
            <dt>Publication</dt>
            <dd>
              {config.publication_enabled
                ? config.publication_fence_verified
                  ? "Enabled, fence verified"
                  : "Unavailable"
                : "Disabled"}
            </dd>
          </div>
          <div>
            <dt>Approved routes</dt>
            <dd>{config.route_count}</dd>
          </div>
        </dl>
      </section>
      <section className="authority-ledger">
        <h2>Runtime authority</h2>
        <dl>
          <Identity label="Status" value={status.identity} />
          <Identity
            label="Configuration"
            value={status.configuration_identity}
          />
          <Identity
            label="Database authority"
            value={config.database_authority_identity ?? ""}
          />
          <Identity
            label="Rate-limit authority"
            value={config.rate_limit_authority_identity ?? ""}
          />
          <Identity
            label="Route inventory"
            value={config.route_inventory_identity ?? ""}
          />
          <Identity
            label="Runtime policy"
            value={config.runtime_policy_identity ?? ""}
          />
        </dl>
        <p>
          These identities describe non-secret authority. They do not expose
          credentials, source, prompts, or provider responses.
        </p>
      </section>
      <section className="spine-panel full">
        <div className="section-head">
          <div>
            <h2>Service readiness</h2>
            <p>Startup reconciliation boundaries</p>
          </div>
        </div>
        {status.components.length === 0 ? (
          <p className="note">
            No supervised background service is configured.
          </p>
        ) : (
          <ol className="runtime-list">
            {status.components.map((component) => (
              <li key={component.name}>
                <strong>{component.name.replaceAll("_", " ")}</strong>
                <Status value={component.state} />
              </li>
            ))}
          </ol>
        )}
      </section>
      <section className="spine-panel full">
        <div className="section-head">
          <div>
            <h2>Handler authority</h2>
            <p>{config.handlers.length} exact handler bindings</p>
          </div>
        </div>
        {config.handlers.length === 0 ? (
          <p className="note">
            No review handler is configured for this repository.
          </p>
        ) : (
          <dl>
            {config.handlers.map((handler) => (
              <Identity
                key={`${handler.kind}:${handler.identity}`}
                label={handler.kind.replaceAll("_", " ")}
                value={handler.identity}
              />
            ))}
          </dl>
        )}
      </section>
    </div>
  );
}

const SetupConsole = lazy(() => import("./SetupApp"));
class SetupLoadBoundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <div className="setup-loading setup-load-error" role="alert">
        <strong>Setup interface could not load</strong>
        <span>Reload this local page to try again.</span>
        <button type="button" onClick={() => window.location.reload()}>
          Reload setup
        </button>
      </div>
    ) : (
      this.props.children
    );
  }
}
export function App() {
  return window.location.pathname === "/console/setup" ? (
    <SetupLoadBoundary>
      <Suspense
        fallback={
          <div className="setup-loading" role="status">
            Loading protected setup
          </div>
        }
      >
        <SetupConsole />
      </Suspense>
    </SetupLoadBoundary>
  ) : (
    <ReviewConsole />
  );
}

function ReviewConsole() {
  const [scope, setScope] = useState<Scope>(rememberedScope);
  const [token, setToken] = useState("");
  const [receipt, setReceipt] = useState<RunReceipt | null>(null);
  const [diagnostics, setDiagnostics] = useState<DiagnosticSet | null>(null);
  const [diagnosticNote, setDiagnosticNote] = useState("");
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus | null>(
    null,
  );
  const [runtimeNote, setRuntimeNote] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<View>("overview");
  const [selectedTask, setSelectedTask] = useState("");
  const operationRef = useRef(0);
  const selected = useMemo(
    () =>
      receipt?.tasks.find((task) => task.key === selectedTask) ??
      receipt?.tasks[0],
    [receipt, selectedTask],
  );
  async function connect(nextScope: Scope, nextToken: string) {
    const operation = ++operationRef.current;
    setBusy(true);
    setError("");
    setDiagnosticNote("");
    setRuntimeNote("");
    try {
      const next = await fetchRun(nextScope, nextToken);
      if (operation !== operationRef.current) return;
      setScope(nextScope);
      setToken(nextToken);
      setReceipt(next);
      setSelectedTask(next.tasks[0]?.key ?? "");
      try {
        sessionStorage.setItem("open-trestle-scope", JSON.stringify(nextScope));
      } catch {}
      if (operation !== operationRef.current) return;
      try {
        const nextDiagnostics = await fetchDiagnostics(nextScope, nextToken);
        if (operation !== operationRef.current) return;
        setDiagnostics(nextDiagnostics);
      } catch (err) {
        if (operation !== operationRef.current) return;
        setDiagnostics(null);
        setDiagnosticNote(
          err instanceof ApiError && err.code === "not_found"
            ? "Review diagnostics are not available for this run yet."
            : "Review diagnostics could not be loaded.",
        );
      }
      if (operation !== operationRef.current) return;
      try {
        const nextRuntime = await fetchRuntimeStatus(nextScope, nextToken);
        if (operation !== operationRef.current) return;
        setRuntimeStatus(nextRuntime);
      } catch {
        if (operation !== operationRef.current) return;
        setRuntimeStatus(null);
        setRuntimeNote("Runtime status could not be loaded with this token.");
      }
    } catch (err) {
      if (operation !== operationRef.current) return;
      setToken("");
      setReceipt(null);
      setDiagnostics(null);
      setRuntimeStatus(null);
      setError(
        err instanceof ApiError ? err.message : "The run could not be loaded.",
      );
    } finally {
      if (operation === operationRef.current) setBusy(false);
    }
  }
  function disconnect() {
    operationRef.current++;
    setBusy(false);
    setToken("");
    setReceipt(null);
    setDiagnostics(null);
    setRuntimeStatus(null);
    setRuntimeNote("");
    setError("");
  }
  if (!receipt)
    return (
      <div className="app-shell welcome">
        <a className="skip-link" href="#main">
          Skip to main content
        </a>
        <Brand />
        <main id="main">
          <Locator initial={scope} onConnect={connect} busy={busy} />
          {error && (
            <div className="error-banner" role="alert">
              <StatusIcon value="failed" />
              <div>
                <strong>Connection failed</strong>
                <p>{error}</p>
              </div>
            </div>
          )}
          <TrustNotes />
        </main>
      </div>
    );
  const completed = receipt.tasks.filter(
    (task) => task.status === "succeeded",
  ).length;
  const primaryHeading = primaryRunHeading(
    receipt,
    diagnostics,
    diagnosticNote,
    busy,
  );
  return (
    <div className="app-shell console">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <aside className="rail">
        <Brand />
        <nav aria-label="Console">
          <button
            className={view === "overview" ? "active" : ""}
            onClick={() => setView("overview")}
            aria-pressed={view === "overview"}
          >
            Overview
          </button>
          <button
            className={view === "tasks" ? "active" : ""}
            onClick={() => setView("tasks")}
            aria-pressed={view === "tasks"}
          >
            Tasks <span>{receipt.tasks.length}</span>
          </button>
          <button
            className={view === "findings" ? "active" : ""}
            onClick={() => setView("findings")}
            aria-pressed={view === "findings"}
          >
            Review{" "}
            <span>
              {diagnostics ? diagnosticItemCount(diagnostics) : "n/a"}
            </span>
          </button>
          <button
            className={view === "runtime" ? "active" : ""}
            onClick={() => setView("runtime")}
            aria-pressed={view === "runtime"}
          >
            Runtime <span>{runtimeStatus?.ready ? "ready" : "n/a"}</span>
          </button>
        </nav>
        <div className="rail-foot">
          <p>
            {scope.tenant}
            <br />
            <strong>{scope.repository}</strong>
          </p>
          <button onClick={disconnect}>Change scope</button>
        </div>
      </aside>
      <header className="mobile-head">
        <Brand />
        <button onClick={disconnect}>Change</button>
      </header>
      <main id="main" className="run-main">
        <header className="run-header">
          <div>
            <div className="scope-line">
              <span>{scope.tenant}</span>
              <span>/</span>
              <span>{scope.repository}</span>
              <span>/</span>
              <strong>{scope.run}</strong>
            </div>
            <h1>{primaryHeading}</h1>
            <p>
              Journal revision {receipt.revision} · Updated{" "}
              {new Date(receipt.last_occurred_at_milliseconds).toLocaleString()}
            </p>
          </div>
          <div className="header-actions">
            <div
              className="operational-status"
              aria-label={`Operational run status ${receipt.status}`}
            >
              <span>Operational run status</span>
              <Status value={receipt.status} />
            </div>
            <button
              className="secondary-button"
              disabled={busy}
              onClick={() => connect(scope, token)}
            >
              Refresh
            </button>
          </div>
        </header>
        <nav className="mobile-tabs" aria-label="Run views">
          {(["overview", "tasks", "findings", "runtime"] as View[]).map(
            (item) => (
              <button
                key={item}
                aria-pressed={view === item}
                onClick={() => setView(item)}
              >
                {item === "findings" ? "review" : item}
              </button>
            ),
          )}
        </nav>
        {view === "overview" && (
          <div className="overview-grid">
            <section className="run-summary">
              <h2>Run state</h2>
              <div className="summary-line">
                <strong>{completed}</strong>
                <span>of {receipt.tasks.length} tasks succeeded</span>
              </div>
              <progress
                className="progress-track"
                aria-label={`${completed} of ${receipt.tasks.length} tasks succeeded`}
                value={completed}
                max={receipt.tasks.length}
              />
              <dl>
                <div>
                  <dt>Failure</dt>
                  <dd>{receipt.failure || "None"}</dd>
                </div>
                <div>
                  <dt>Required tasks</dt>
                  <dd>
                    {receipt.tasks.filter((task) => task.required).length}
                  </dd>
                </div>
                <div>
                  <dt>
                    {diagnostics?.schema_version === 6
                      ? "Deterministic observations"
                      : "Verified findings"}
                  </dt>
                  <dd>
                    {diagnostics
                      ? diagnosticItemCount(diagnostics)
                      : "Not available"}
                  </dd>
                </div>
              </dl>
              {diagnosticNote && (
                <p className="note">
                  <StatusIcon value="unavailable" />
                  {diagnosticNote}
                </p>
              )}
            </section>
            <section className="authority-ledger">
              <h2>Evidence boundary</h2>
              <dl>
                <Identity label="Run receipt" value={receipt.identity} />
                <Identity label="Plan" value={receipt.plan_identity} />
                <Identity label="Head" value={receipt.head_identity} />
                <Identity
                  label="Diagnostic set"
                  value={diagnostics?.identity ?? ""}
                />
                <Identity
                  label="Terminal output"
                  value={receipt.output_identity}
                />
              </dl>
              <p>
                Identities prove exact lineage. They do not grant publication or
                provider authority.
              </p>
            </section>
            <section className="spine-panel">
              <div className="section-head">
                <div>
                  <h2>Execution depth</h2>
                  <p>Replay-derived task state</p>
                </div>
                <button onClick={() => setView("tasks")}>Inspect all</button>
              </div>
              <TaskSpine
                tasks={receipt.tasks}
                selected={selected?.key ?? ""}
                onSelect={setSelectedTask}
              />
            </section>
          </div>
        )}
        {view === "tasks" && (
          <div className="task-layout">
            <section className="spine-panel full">
              <div className="section-head">
                <div>
                  <h2>Task journal</h2>
                  <p>Each mark is one planned execution boundary.</p>
                </div>
              </div>
              <TaskSpine
                tasks={receipt.tasks}
                selected={selected?.key ?? ""}
                onSelect={setSelectedTask}
              />
            </section>
            <aside className="inspector" aria-label="Task evidence inspector">
              <TaskInspector task={selected} />
            </aside>
          </div>
        )}
        {view === "findings" && (
          <section className="findings-view">
            <div className="section-head">
              <div>
                <h2>Human review queue</h2>
                <p>
                  Verified findings and deterministic observations stay
                  separate.
                </p>
              </div>
              {diagnostics && (
                <span className="set-count">
                  {diagnosticItemCount(diagnostics)}{" "}
                  {diagnosticItemCount(diagnostics) === 1
                    ? diagnostics.schema_version === 6
                      ? "observation"
                      : "finding"
                    : diagnostics.schema_version === 6
                      ? "observations"
                      : "findings"}
                </span>
              )}
            </div>
            <CoverageLedger set={diagnostics} />
            <Findings set={diagnostics} />
            {diagnosticNote && (
              <p className="note">
                <StatusIcon value="unavailable" />
                {diagnosticNote}
              </p>
            )}
          </section>
        )}
        {view === "runtime" && (
          <RuntimeView status={runtimeStatus} note={runtimeNote} />
        )}
      </main>
    </div>
  );
}
function Brand({ subtitle = "Evidence console" }: { subtitle?: string }) {
  return (
    <div className="brand">
      <span className="brand-mark">
        <ShieldCheck className="brand-shield" aria-hidden="true" />
      </span>
      <span>
        <strong>Open Trestle</strong>
        <small>{subtitle}</small>
      </span>
    </div>
  );
}
function TrustNotes() {
  return (
    <section className="trust-notes" aria-label="Console safety">
      <div>
        <InstrumentIcon />
        <h2>Read-only by design</h2>
        <p>
          This console inspects durable state. It cannot approve, publish, run
          tools, or change policy.
        </p>
      </div>
      <div>
        <InstrumentIcon />
        <h2>Exact scope</h2>
        <p>
          Review requests name one tenant, repository, and run. Runtime requests
          name one tenant and repository. Cross-scope responses are rejected.
        </p>
      </div>
      <div>
        <StatusIcon value="passed" />
        <h2>Verified means verified</h2>
        <p>
          Candidate output is never presented as a finding. Inconclusive work
          stays visible in run state.
        </p>
      </div>
    </section>
  );
}
