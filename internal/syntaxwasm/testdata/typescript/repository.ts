import type { Connection, PoolConfig } from "./driver";
import type * as Types from "./types";
import Logger from "./logger";
import { EventEmitter, once as onceEvent } from "events";
import * as path from "path";
import fs = require("fs");
import config = require("./config");

export * from "./errors";
export * as helpers from "./helpers";

declare const __DEV__: boolean;
declare function hrtime(): bigint;
declare module "legacy-orm" {
  export interface LegacyRow {
    id: number;
    [column: string]: unknown;
  }
  export function connect(url: string): Promise<void>;
}

/** Marker decorators used by the entity layer. */
function Entity(table: string): ClassDecorator {
  return (target) => {
    Reflect.defineMetadata("table", table, target);
  };
}

function Column(name?: string): PropertyDecorator {
  return (target, key) => {
    Reflect.defineMetadata("column", name ?? String(key), target, key);
  };
}

function Traced(): MethodDecorator {
  return (_target, key, descriptor) => {
    const original = descriptor.value as unknown as (...args: unknown[]) => unknown;
    descriptor.value = function (this: unknown, ...args: unknown[]) {
      if (__DEV__) {
        console.debug(`call ${String(key)}`);
      }
      return original.apply(this, args);
    } as unknown as typeof descriptor.value;
  };
}

function Inject(token: string): ParameterDecorator {
  return (target, key, index) => {
    Reflect.defineMetadata(`inject:${index}`, token, target, key as string | symbol);
  };
}

export enum IsolationLevel {
  ReadCommitted = "READ COMMITTED",
  RepeatableRead = "REPEATABLE READ",
  Serializable = "SERIALIZABLE",
}

export const enum SortOrder {
  Asc,
  Desc = 10,
  Natural = Asc | Desc,
}

export interface Identifiable<K extends string | number = number> {
  readonly id: K;
}

export interface Timestamped {
  createdAt: Date;
  updatedAt?: Date;
}

export interface Named {
  name: string;
}

export interface Disposable {
  dispose(): void | Promise<void>;
}

export interface Row extends Identifiable, Timestamped, Named {
  readonly version: number;
  tags?: string[];
  [extra: string]: unknown;
}

export interface Clock {
  (): Date;
  readonly resolution: number;
  new (offset: number): Clock;
}

export interface Dictionary<V> {
  [key: string]: V;
  [index: number]: V;
}

export type WithAudit<T> = T & { auditedBy: string; auditedAt: Date };
export type Mutable<T> = { -readonly [P in keyof T]-?: T[P] };
export type Getters<T> = {
  [P in keyof T as `get${Capitalize<string & P>}`]: () => T[P];
};
export type Unwrap<T> = T extends Promise<infer U> ? Unwrap<U> : T;
export type ElementOf<T> = T extends readonly (infer E)[] ? E : never;
export type TableName<S extends string> = `tbl_${Lowercase<S>}`;
export type Predicate<T> = (value: T, index: number) => boolean;

const DEFAULT_PAGE = { size: 25, max: 200 } as const;
const OPERATORS = ["=", "<>", "<", ">", "LIKE"] as const;
type Operator = (typeof OPERATORS)[number];

export namespace Validation {
  export interface Rule<T> {
    check(value: T): boolean;
    message: string;
  }

  export const required: Rule<unknown> = {
    check: (v) => v !== null && v !== undefined,
    message: "value is required",
  };

  export namespace Strings {
    export function minLength(n: number): Rule<string> {
      return { check: (v) => v.length >= n, message: `must have at least ${n} characters` };
    }
  }
}

namespace Metrics.Counters {
  export let hits = 0;
  export function bump(by = 1): number {
    hits += by;
    return hits;
  }
}

export function isRow(value: unknown): value is Row {
  return typeof value === "object" && value !== null && "id" in value && "version" in value;
}

export function assertDefined<T>(value: T | undefined, label: string): asserts value is T {
  if (value === undefined) {
    throw new TypeError(`${label} must be defined`);
  }
}

export function assertPositive(n: number): asserts n {
  if (n <= 0) throw new RangeError("expected a positive number");
}

export class QueryError extends Error {
  constructor(
    message: string,
    public readonly sql: string,
    private readonly params: readonly unknown[] = [],
  ) {
    super(message);
    this.name = "QueryError";
  }

  get paramCount(): number {
    return this.params.length;
  }
}

export class QueryBuilder<T extends Row = Row, Mode extends "select" | "count" = "select"> {
  private readonly clauses: string[] = [];
  private readonly values: unknown[] = [];
  private limitValue?: number;
  protected orderBy: [string, SortOrder][] = [];
  static instances = 0;

  constructor(private readonly table: TableName<string> | string) {
    QueryBuilder.instances++;
  }

  where<K extends keyof T & string>(column: K, op: Operator, value: T[K]): this {
    this.clauses.push(`${column} ${op} ?`);
    this.values.push(value);
    return this;
  }

  order(column: string, direction: SortOrder = SortOrder.Asc): this {
    this.orderBy.push([column, direction]);
    return this;
  }

  limit(n: number): this {
    assertPositive(n);
    this.limitValue = Math.min(n, DEFAULT_PAGE.max);
    return this;
  }

  build(): { sql: string; params: unknown[] };
  build(withSemicolon: boolean): { sql: string; params: unknown[] };
  build(withSemicolon?: boolean) {
    let sql = `SELECT * FROM ${this.table}`;
    if (this.clauses.length > 0) {
      sql += " WHERE " + this.clauses.join(" AND ");
    }
    if (this.orderBy.length) {
      const parts = this.orderBy.map(([c, d]) => `${c} ${d === SortOrder.Desc ? "DESC" : "ASC"}`);
      sql += ` ORDER BY ${parts.join(", ")}`;
    }
    if (this.limitValue !== undefined) sql += ` LIMIT ${this.limitValue}`;
    return { sql: withSemicolon ? sql + ";" : sql, params: [...this.values] };
  }
}

export abstract class BaseRepository<T extends Row, K extends string | number = number>
  implements Disposable, Named
{
  abstract readonly tableName: string;
  protected abstract hydrate(raw: Record<string, unknown>): T;
  public name = "repository";
  private static registry = new Map<string, BaseRepository<Row>>();
  protected readonly cache = new Map<K, T>();
  private disposed = false;

  constructor(protected readonly conn: Connection, protected log?: Logger) {
    this.log?.info("repository created");
  }

  get size(): number {
    return this.cache.size;
  }

  set capacity(value: number) {
    assertPositive(value);
    this.log?.info(`capacity set to ${value}`);
  }

  static register(repo: BaseRepository<Row>): void {
    BaseRepository.registry.set(repo.tableName, repo);
  }

  @Traced()
  async findById(@Inject("id") id: K): Promise<T | undefined> {
    const hit = this.cache.get(id);
    if (hit) return hit;
    const { rows } = await this.conn.query(`SELECT * FROM ${this.tableName} WHERE id = ?`, [id]);
    const first = rows[0];
    return first ? this.remember(id, this.hydrate(first)) : undefined;
  }

  async findAll(filter?: Predicate<T>): Promise<T[]> {
    const { rows } = await this.conn.query(`SELECT * FROM ${this.tableName}`);
    const all = rows.map((r) => this.hydrate(r));
    return filter ? all.filter(filter) : all;
  }

  protected remember(id: K, entity: T): T {
    this.cache.set(id, entity);
    return entity;
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    this.cache.clear();
  }
}

@Entity("users")
export class User implements Row {
  readonly id!: number;
  readonly version = 1;
  createdAt = new Date();
  [extra: string]: unknown;

  @Column("user_name")
  name = "";

  @Column()
  email?: string;

  tags?: string[];
}

export class UserRepository extends BaseRepository<User> implements Timestamped, Disposable {
  readonly tableName = "users";
  createdAt = new Date();

  protected hydrate(raw: Record<string, unknown>): User {
    return Object.assign(new User(), raw);
  }

  async findByEmail(email: string): Promise<User | undefined> {
    const builder = new QueryBuilder<User>(this.tableName).where("email", "=", email).limit(1);
    const { sql, params } = builder.build(true);
    const result = await this.conn.query(sql, params);
    return result.rows.length ? this.hydrate(result.rows[0]!) : undefined;
  }

  async rename(id: number, next: string): Promise<void> {
    const user = await this.findById(id);
    assertDefined(user, "user");
    user.name = next;
    await this.conn.query("UPDATE users SET name = ? WHERE id = ?", [next, id]);
  }
}

export class UnitOfWork extends EventEmitter {
  private readonly pending: Array<() => Promise<void>> = [];
  private state: "idle" | "open" | "closed" = "idle";
  private readonly counters = new Map<string, number>();
  private readonly seen = new Set<number>();

  constructor(
    private readonly conn: Connection,
    readonly isolation: IsolationLevel = IsolationLevel.ReadCommitted,
  ) {
    super();
  }

  enlist(work: () => Promise<void>): void {
    this.pending.push(work);
    const prior = this.counters.get("enlisted") ?? 0;
    this.counters.set("enlisted", prior + 1);
  }

  async commit(): Promise<number> {
    if (this.state === "closed") throw new Error("unit of work is closed");
    this.state = "open";
    try {
      await this.conn.query(`BEGIN ISOLATION LEVEL ${this.isolation}`);
      for (const work of this.pending) {
        await work();
      }
      await this.conn.query("COMMIT");
      this.emit("committed", this.pending.length);
      return this.pending.length;
    } catch (err) {
      await this.conn.query("ROLLBACK");
      this.emit("rolledback", err);
      throw err;
    } finally {
      this.pending.length = 0;
      this.state = "closed";
    }
  }
}

export async function withTransaction<R>(
  conn: Connection,
  body: (uow: UnitOfWork) => Promise<R>,
): Promise<R> {
  const uow = new UnitOfWork(conn, IsolationLevel.Serializable);
  const result = await body(uow);
  await uow.commit();
  return result;
}

export const groupBy = <T, K extends PropertyKey>(items: readonly T[], key: (item: T) => K) =>
  items.reduce(
    (acc, item) => {
      (acc[key(item)] ||= []).push(item);
      return acc;
    },
    {} as Record<K, T[]>,
  );

export const identity = <T,>(value: T): T => value;

const settings = {
  retries: 3,
  backoff: [100, 400, 1600],
  schema: path.join(config.root, "schema.sql"),
} satisfies Record<string, unknown>;

export function describe(repo?: UserRepository): string {
  const label = repo?.name.toUpperCase() ?? "none";
  const rows = repo?.findAll?.();
  const size = repo!.size;
  return `${label}:${size}:${rows === undefined ? 0 : 1}`;
}

export async function main(): Promise<void> {
  const counts = new Map<string, number>();
  const index = new Map<number, Set<string>>();
  const log = new Logger("repository");
  counts.set("boot", Metrics.Counters.bump());
  index.set(1, new Set<string>(["a", "b"]));
  const schemaText = fs.readFileSync(settings.schema, "utf8");
  log.info(`schema bytes: ${schemaText.length}`);
  await onceEvent(new EventEmitter(), "ready");
}

export { QueryBuilder as Builder, UnitOfWork as Work };
export default UserRepository;
