import type { Request } from "express";
import fs = require("fs");

export interface Store<T> extends Base<T> {
  get(key: string): T | undefined;
  size: number;
}

export type Id = string | number;

export enum Color { Red, Green = 2 }

@Injectable()
export abstract class Repo<T> implements Store<T> {
  private items = new Map<string, T>();
  constructor(private readonly db: Db.Client) {}
  get(key: string): T | undefined { return this.items.get(key); }
  abstract size: number;
}

namespace Util { export function id(x: Id): Id { return x; } }
declare function external(r: Request): void;
export const View = (p: Props) => <Layout.Main><Item id={p.id} /></Layout.Main>;
