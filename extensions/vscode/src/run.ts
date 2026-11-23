import { execFile, spawn } from "node:child_process";
export const reviewArguments = [
  "review",
  "--format",
  "sarif",
  "--stop-on-stdin-close",
] as const;
const maxStdoutBytes = 5 * 1024 * 1024;
const maxStderrLines = 20;
const maxLineBytes = 16 * 1024;
export interface RunOptions {
  command: string;
  args: readonly string[];
  cwd: string;
  env: Record<string, string>;
  onStderrLine: (line: string) => void;
  graceMs?: number;
}
export interface RunResult {
  code: number | null;
  stdout: string;
  stderrTail: string[];
  canceled: boolean;
  overflow: boolean;
  error?: NodeJS.ErrnoException;
}
export interface Run {
  result: Promise<RunResult>;
  cancel(): void;
}
// startRun runs one command without a shell. Stopping ends its standard
// input, then sends SIGTERM and finally SIGKILL, each after the grace period.
export function startRun(options: RunOptions): Run {
  const grace = options.graceMs ?? 5000;
  const child = spawn(options.command, options.args, {
    cwd: options.cwd,
    env: options.env,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  const chunks: Buffer[] = [];
  const tail: string[] = [];
  const timers: NodeJS.Timeout[] = [];
  let size = 0;
  let partial = "";
  let canceled = false;
  let overflow = false;
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    child.stdin.end();
    timers.push(
      setTimeout(() => child.kill("SIGTERM"), grace),
      setTimeout(() => child.kill("SIGKILL"), 2 * grace),
    );
  };
  const line = (text: string) => {
    const value = text.replace(/\r$/, "");
    if (value === "") return;
    tail.push(value);
    if (tail.length > maxStderrLines) tail.shift();
    options.onStderrLine(value);
  };
  child.stdin.on("error", () => {});
  child.stdout.on("data", (chunk: Buffer) => {
    if (overflow) return;
    size += chunk.length;
    if (size > maxStdoutBytes) {
      overflow = true;
      chunks.length = 0;
      stop();
      return;
    }
    chunks.push(chunk);
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (text: string) => {
    const lines = (partial + text).split("\n");
    partial = (lines.pop() ?? "").slice(0, maxLineBytes);
    for (const value of lines) line(value.slice(0, maxLineBytes));
  });
  const result = new Promise<RunResult>((resolve) => {
    const finish = (code: number | null, error?: NodeJS.ErrnoException) => {
      timers.forEach(clearTimeout);
      line(partial);
      partial = "";
      const stdout = Buffer.concat(chunks).toString("utf8");
      resolve({ code, stdout, stderrTail: tail, canceled, overflow, error });
    };
    child.on("error", (error) => {
      if (child.pid === undefined) finish(null, error);
    });
    child.on("close", (code) => finish(code));
  });
  return {
    result,
    cancel() {
      canceled = true;
      stop();
    },
  };
}
// repositoryRoot is the top folder of the Git checkout that holds cwd.
export function repositoryRoot(
  cwd: string,
  env: Record<string, string>,
): Promise<string | undefined> {
  return new Promise((resolve) =>
    execFile(
      "git",
      ["rev-parse", "--show-toplevel"],
      { cwd, env, shell: false, timeout: 10000, windowsHide: true },
      (error, stdout) =>
        resolve(error ? undefined : stdout.trim() || undefined),
    ),
  );
}
