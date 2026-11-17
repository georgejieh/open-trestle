// Dashboard module: metric widgets, data access and layout.
import type { ReactNode, ComponentType } from "react";
import React, { useState, useEffect, useMemo, useCallback } from "react";
import { Layout, Card as BaseCard } from "./ui/layout";
import type { ChartSeries } from "./charts";
import { formatNumber, formatPercent } from "./format";

declare function track(event: string, payload?: Record<string, unknown>): void;

declare module "*.svg" {
  const url: string;
  export default url;
}

export enum Status {
  Idle = "idle",
  Loading = "loading",
  Ready = "ready",
  Failed = "failed",
}

export const enum Density {
  Compact = 1,
  Comfortable = 2,
  Spacious = 3,
}

enum Direction {
  Up,
  Down,
  Flat,
}

export interface Identified {
  readonly id: string;
}

export interface Metric<T = number> extends Identified {
  label: string;
  value: T;
  unit?: string;
  readonly updatedAt: Date;
  format(value: T): string;
}

export interface Repository<TItem extends Identified, TKey = string> {
  get(key: TKey): Promise<TItem | undefined>;
  list(filter?: Partial<TItem>): Promise<TItem[]>;
  save(item: TItem): Promise<void>;
}

export type MetricKind = "count" | "ratio" | "duration";

export type WidgetState<T> =
  | { status: Status.Idle }
  | { status: Status.Loading; startedAt: number }
  | { status: Status.Ready; data: T }
  | { status: Status.Failed; error: Error };

type Nullable<T> = { [K in keyof T]: T[K] | null };
type Mutable<T> = { -readonly [K in keyof T]: T[K] };
type Unwrap<T> = T extends Promise<infer U> ? U : T;
type ElementOf<T> = T extends readonly (infer E)[] ? E : never;

export type MetricMap = Record<MetricKind, Metric[]>;

const DEFAULT_REFRESH_MS = 30_000;

const palette = {
  primary: "#2563eb",
  danger: "#dc2626",
  muted: "#6b7280",
} satisfies Record<string, string>;

function Log(prefix: string) {
  return function <T extends new (...args: any[]) => object>(target: T) {
    track("class-registered", { prefix, name: target.name });
    return target;
  };
}

function Measure(
  _target: object,
  key: string,
  descriptor: PropertyDescriptor,
): PropertyDescriptor {
  const original = descriptor.value as (...args: unknown[]) => unknown;
  descriptor.value = function (this: unknown, ...args: unknown[]) {
    const started = performance.now();
    const result = original.apply(this, args);
    track("measure", { key, ms: performance.now() - started });
    return result;
  };
  return descriptor;
}

export namespace Stats {
  export function mean(values: readonly number[]): number {
    if (values.length === 0) return 0;
    return values.reduce((sum, v) => sum + v, 0) / values.length;
  }

  export function percentile(values: number[], p: number): number {
    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
    return sorted[index] ?? 0;
  }

  export const EPSILON = 1e-9;
}

export function groupBy<T, K extends string | number>(
  items: readonly T[],
  keyOf: (item: T) => K,
): Map<K, T[]> {
  const groups = new Map<K, T[]>();
  for (const item of items) {
    const key = keyOf(item);
    const bucket = groups.get(key) ?? [];
    bucket.push(item);
    groups.set(key, bucket);
  }
  return groups;
}

export function pick<T extends object, K extends keyof T>(source: T, keys: K[]): Pick<T, K> {
  const out = {} as Pick<T, K>;
  for (const key of keys) {
    out[key] = source[key];
  }
  return out;
}

export function trendOf(previous: number, current: number): Direction {
  if (Math.abs(current - previous) < Stats.EPSILON) return Direction.Flat;
  return current > previous ? Direction.Up : Direction.Down;
}

export abstract class BaseRepository<T extends Identified> implements Repository<T> {
  protected cache = new Map<string, T>();

  abstract readonly endpoint: string;
  abstract fetchAll(): Promise<T[]>;

  async get(key: string): Promise<T | undefined> {
    if (this.cache.has(key)) {
      return this.cache.get(key);
    }
    const all = await this.fetchAll();
    all.forEach((item) => this.cache.set(item.id, item));
    return this.cache.get(key);
  }

  async list(filter?: Partial<T>): Promise<T[]> {
    const all = await this.fetchAll();
    if (!filter) return all;
    const entries = Object.entries(filter) as [keyof T, unknown][];
    return all.filter((item) => entries.every(([k, v]) => item[k] === v));
  }

  async save(item: T): Promise<void> {
    this.cache.set(item.id, item);
  }
}

@Log("api")
export class MetricApi extends BaseRepository<Metric> {
  readonly endpoint = "/api/metrics";

  constructor(
    private readonly baseUrl: string,
    private readonly timeoutMs: number = 5000,
    public retries = 2,
  ) {
    super();
  }

  @Measure
  async fetchAll(): Promise<Metric[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(`${this.baseUrl}${this.endpoint}`, {
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(`request failed with ${response.status}`);
      }
      const rows = (await response.json()) as Array<Omit<Metric, "format" | "updatedAt">>;
      return rows.map((row) => ({
        ...row,
        updatedAt: new Date(),
        format: (value: number) => formatNumber(value),
      }));
    } finally {
      clearTimeout(timer);
    }
  }
}

export function useAsync<T>(loader: () => Promise<T>, deps: unknown[] = []): WidgetState<T> {
  const [state, setState] = useState<WidgetState<T>>({ status: Status.Idle });

  useEffect(() => {
    let cancelled = false;
    setState({ status: Status.Loading, startedAt: Date.now() });
    loader()
      .then((data) => {
        if (!cancelled) setState({ status: Status.Ready, data });
      })
      .catch((error: Error) => {
        if (!cancelled) setState({ status: Status.Failed, error });
      });
    return () => {
      cancelled = true;
    };
  }, deps);

  return state;
}

export function useInterval(callback: () => void, delay: number | null): void {
  useEffect(() => {
    if (delay === null) return;
    const handle = window.setInterval(callback, delay);
    return () => window.clearInterval(handle);
  }, [callback, delay]);
}

interface TrendBadgeProps {
  direction: Direction;
  delta?: number;
}

const TrendBadge = ({ direction, delta }: TrendBadgeProps) => {
  const symbol = direction === Direction.Up ? "+" : direction === Direction.Down ? "-" : "=";
  return (
    <span className="badge" data-direction={Direction[direction]}>
      {symbol}
      {delta !== undefined && formatPercent(delta)}
    </span>
  );
};

interface MetricCardProps {
  metric: Metric;
  previous?: number;
  density?: Density;
  onSelect?: (id: string) => void;
  children?: ReactNode;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  metric,
  previous,
  density = Density.Comfortable,
  onSelect,
  children,
}) => {
  const direction = previous === undefined ? Direction.Flat : trendOf(previous, metric.value);
  const handleClick = useCallback(() => onSelect?.(metric.id), [metric.id, onSelect]);

  return (
    <BaseCard onClick={handleClick} style={{ padding: density * 4, borderColor: palette.muted }}>
      <h3>{metric.label}</h3>
      <p>
        {metric.format(metric.value)}
        {metric.unit ? <small> {metric.unit}</small> : null}
      </p>
      <TrendBadge direction={direction} delta={previous ? (metric.value - previous) / previous : undefined} />
      {children}
    </BaseCard>
  );
};

interface MetricGridProps {
  metrics: Metric[];
  filter: MetricKind | "all";
  onSelect: (id: string) => void;
}

export function MetricGrid({ metrics, filter, onSelect }: MetricGridProps) {
  const visible = useMemo(
    () => (filter === "all" ? metrics : metrics.filter((m) => m.unit === filter)),
    [metrics, filter],
  );

  if (visible.length === 0) {
    return <p className="empty">No metrics to show.</p>;
  }

  return (
    <ul className="grid">
      {visible.map((metric) => (
        <li key={metric.id}>
          <MetricCard metric={metric} onSelect={onSelect} />
        </li>
      ))}
    </ul>
  );
}

function Sparkline({ series }: { series: ChartSeries }) {
  const peak = Math.max(...series.points.map((p) => p.y));
  return (
    <svg viewBox="0 0 100 20" role="img" aria-label={series.name}>
      {series.points.map((p, i) => (
        <rect key={i} x={i * 4} y={20 - (p.y / peak) * 20} width={3} height={(p.y / peak) * 20} />
      ))}
    </svg>
  );
}

function withBoundary<P extends object>(Inner: ComponentType<P>): ComponentType<P> {
  return function Bounded(props: P) {
    const [failed, setFailed] = useState(false);
    useEffect(() => {
      const listener = () => setFailed(true);
      window.addEventListener("error", listener);
      return () => window.removeEventListener("error", listener);
    }, []);
    return failed ? <div role="alert">Something went wrong.</div> : <Inner {...props} />;
  };
}

const SafeGrid = withBoundary(MetricGrid);

export default function Dashboard({ api }: { api: MetricApi }) {
  const [filter, setFilter] = useState<MetricKind | "all">("all");
  const [selected, setSelected] = useState<string | null>(null);
  const state = useAsync(() => api.list(), [api]);
  const root = document.getElementById("root")!;

  useInterval(() => track("heartbeat", { filter }), DEFAULT_REFRESH_MS);

  const total = useMemo(() => {
    if (state.status !== Status.Ready) return 0;
    return Stats.mean(state.data.map((m) => m.value));
  }, [state]);

  return (
    <Layout>
      <Layout.Sidebar width={240}>
        <nav>
          {(["all", "count", "ratio", "duration"] as const).map((kind) => (
            <button key={kind} disabled={kind === filter} onClick={() => setFilter(kind)}>
              {kind}
            </button>
          ))}
        </nav>
      </Layout.Sidebar>
      <Layout.Content title="Overview" mount={root}>
        <>
          {state.status === Status.Loading && <p>Loading...</p>}
          {state.status === Status.Failed && <p role="alert">{state.error.message}</p>}
          {state.status === Status.Ready && (
            <>
              <p>Average: {formatNumber(total)}</p>
              <SafeGrid metrics={state.data} filter={filter} onSelect={setSelected} />
            </>
          )}
        </>
        {selected ? <aside>Selected: {selected}</aside> : <aside />}
      </Layout.Content>
    </Layout>
  );
}
