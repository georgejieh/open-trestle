// Event bus and job queue utilities.
import EventEmitter from "node:events";
import { setTimeout as sleep, setImmediate as defer } from "node:timers/promises";
import { randomUUID as uuid, createHash } from "node:crypto";
import * as path from "node:path";
import "./polyfills.js";

export * from "./constants.js";
export { Logger, createLogger as makeLogger } from "./logger.js";

const fs = require("node:fs");

const DEFAULT_CONCURRENCY = 4;
const MAX_RETRIES = 3;
let jobCounter = 0;
var legacyMode = false;

export const Priority = Object.freeze({
  LOW: 0,
  NORMAL: 5,
  HIGH: 10,
});

export const registry = {
  handlers: {},
  metrics: { emitted: 0, failed: 0 },
};

registry.handlers.onReady = function () {
  return `ready at ${new Date().toISOString()}`;
};

// A small guard that turns repeated calls into a single one.
function once(fn) {
  let called = false;
  let result;
  return function wrapped(...args) {
    if (!called) {
      called = true;
      result = fn.apply(this, args);
    }
    return result;
  };
}

export const makeId = (prefix = "job") => `${prefix}-${++jobCounter}-${uuid().slice(0, 8)}`;

export function hashPayload(payload) {
  const hash = createHash("sha256");
  hash.update(JSON.stringify(payload ?? null));
  return hash.digest("hex");
}

class Deferred {
  constructor() {
    this.promise = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }
}

export class TypedEmitter extends EventEmitter {
  static defaultMaxListeners = 20;
  static #instances = 0;

  #history = [];
  #limit;

  constructor(options = {}) {
    super();
    const { historyLimit = 50, name = "emitter" } = options;
    this.#limit = historyLimit;
    this.name = name;
    TypedEmitter.#instances += 1;
    this.setMaxListeners(TypedEmitter.defaultMaxListeners);
  }

  static get instances() {
    return TypedEmitter.#instances;
  }

  get history() {
    return [...this.#history];
  }

  set historyLimit(value) {
    if (!Number.isInteger(value) || value < 0) {
      throw new RangeError(`invalid history limit: ${value}`);
    }
    this.#limit = value;
    this.#trim();
  }

  #trim() {
    while (this.#history.length > this.#limit) {
      this.#history.shift();
    }
  }

  #record(event, args) {
    this.#history.push({ event, args, at: Date.now() });
    this.#trim();
  }

  emit(event, ...args) {
    this.#record(event, args);
    registry.metrics.emitted++;
    return super.emit(event, ...args);
  }

  async emitAsync(event, ...args) {
    const listeners = this.listeners(event);
    const results = [];
    for (const listener of listeners) {
      results.push(await listener.apply(this, args));
    }
    return results;
  }

  *replay(filter) {
    for (const entry of this.#history) {
      if (!filter || entry.event === filter) {
        yield entry;
      }
    }
  }

  async *stream(event, { signal } = {}) {
    const queue = [];
    let waiting = null;
    const handler = (...args) => {
      if (waiting) {
        waiting.resolve(args);
        waiting = null;
      } else {
        queue.push(args);
      }
    };
    this.on(event, handler);
    try {
      while (!signal?.aborted) {
        if (queue.length > 0) {
          yield queue.shift();
        } else {
          waiting = new Deferred();
          yield await waiting.promise;
        }
      }
    } finally {
      this.off(event, handler);
    }
  }
}

export default class JobQueue extends TypedEmitter {
  static DEFAULTS = {
    concurrency: DEFAULT_CONCURRENCY,
    retries: MAX_RETRIES,
    backoffMs: 50,
  };

  #pending = [];
  #running = new Map();
  #settings;
  #paused = false;

  constructor(settings = {}) {
    super({ name: "job-queue", historyLimit: 100 });
    this.#settings = { ...JobQueue.DEFAULTS, ...settings };
  }

  static from(tasks, settings) {
    const queue = new JobQueue(settings);
    tasks.forEach((task, index) => queue.add(task, { priority: index }));
    return queue;
  }

  get size() {
    return this.#pending.length + this.#running.size;
  }

  get paused() {
    return this.#paused;
  }

  add(task, { priority = Priority.NORMAL, id = makeId() } = {}) {
    const deferred = new Deferred();
    const job = { id, task, priority, attempts: 0, deferred };
    this.#insert(job);
    this.emit("queued", job.id);
    queueMicrotask(() => this.#drain());
    return deferred.promise;
  }

  #insert(job) {
    const index = this.#pending.findIndex((other) => other.priority < job.priority);
    if (index === -1) {
      this.#pending.push(job);
    } else {
      this.#pending.splice(index, 0, job);
    }
  }

  #drain() {
    while (!this.#paused && this.#running.size < this.#settings.concurrency) {
      const job = this.#pending.shift();
      if (!job) break;
      this.#start(job);
    }
    if (this.size === 0) {
      this.emit("idle");
    }
  }

  #start(job) {
    this.#running.set(job.id, job);
    job.attempts++;
    this.emit("started", job.id, job.attempts);

    Promise.resolve()
      .then(() => job.task({ id: job.id, attempt: job.attempts }))
      .then((value) => {
        job.deferred.resolve(value);
        this.emit("completed", job.id, value);
      })
      .catch(async (error) => {
        if (job.attempts <= this.#settings.retries) {
          await sleep(this.#settings.backoffMs * job.attempts);
          this.#insert(job);
          this.emit("retry", job.id, error);
        } else {
          registry.metrics.failed += 1;
          job.deferred.reject(error);
          this.emit("failed", job.id, error);
        }
      })
      .finally(() => {
        this.#running.delete(job.id);
        this.#drain();
      });
  }

  pause() {
    this.#paused = true;
    return this;
  }

  resume() {
    this.#paused = false;
    this.#drain();
    return this;
  }

  async onIdle() {
    if (this.size === 0) return;
    await new Promise((resolve) => this.once("idle", resolve));
  }

  async drainAll(tasks) {
    const promises = tasks.map((task) => this.add(task));
    const settled = await Promise.allSettled(promises);
    const failures = settled.filter((entry) => entry.status === "rejected");
    return { total: settled.length, failures: failures.length };
  }
}

export const RateLimiter = class {
  #tokens;
  #capacity;
  #refillMs;

  constructor(capacity, refillMs = 1000) {
    this.#capacity = capacity;
    this.#tokens = capacity;
    this.#refillMs = refillMs;
    const timer = setInterval(() => {
      this.#tokens = Math.min(this.#capacity, this.#tokens + 1);
    }, this.#refillMs);
    timer.unref?.();
  }

  tryAcquire() {
    if (this.#tokens > 0) {
      this.#tokens--;
      return true;
    }
    return false;
  }
};

const middleware = {
  logging: (event, args) => {
    console.log(`[bus] ${event}`, args.length);
    return args;
  },
  redact(event, args) {
    return args.map((arg) =>
      typeof arg === "object" && arg !== null ? { ...arg, secret: undefined } : arg,
    );
  },
  async audit(event, args) {
    const line = `${Date.now()} ${event} ${hashPayload(args)}\n`;
    await fs.promises.appendFile(path.join(".", "audit.log"), line);
    return args;
  },
};

export function createBus(options = {}) {
  const emitter = new TypedEmitter(options);
  const stack = [];
  let sealed = false;

  function use(fn) {
    if (sealed) {
      throw new Error("bus is sealed");
    }
    stack.push(fn);
    return api;
  }

  async function publish(event, ...args) {
    sealed = true;
    let current = args;
    for (const fn of stack) {
      current = (await fn(event, current)) ?? current;
    }
    return emitter.emit(event, ...current);
  }

  const api = { use, publish, emitter, subscribe: (e, h) => emitter.on(e, h) };
  return api;
}

export async function loadPlugins(names) {
  const loaded = [];
  for (const name of names) {
    try {
      const mod = await import(`./plugins/${name}.js`);
      loaded.push({ name, install: mod.default ?? mod.install });
    } catch (error) {
      if (error.code !== "ERR_MODULE_NOT_FOUND") {
        throw error;
      }
      console.warn(`plugin ${name} missing`);
    } finally {
      jobCounter += 0;
    }
  }
  return loaded;
}

export async function consume(source, handler) {
  let count = 0;
  for await (const chunk of source) {
    await handler(chunk);
    count++;
    if (count % 100 === 0) {
      await defer();
    }
  }
  return count;
}

export function summarize(queue) {
  const { size, paused } = queue;
  const [first = null, ...rest] = queue.history;
  return {
    size,
    paused,
    first: first?.event,
    remaining: rest.length,
    last: queue.history.at(-1)?.args?.[0],
  };
}

export const timing = {
  start() {
    const began = performance.now();
    return () => performance.now() - began;
  },
  async measure(label, work) {
    const stop = timing.start();
    try {
      return await work();
    } finally {
      console.log(`${label} took ${stop().toFixed(1)}ms`);
    }
  },
};

const scratch = new path.posix.constructor();

export { once, Deferred as DeferredValue, middleware as builtins, legacyMode as legacy };

if (typeof module !== "undefined") {
  module.exports = { once };
}
