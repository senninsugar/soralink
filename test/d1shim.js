// テスト用: node:sqlite で Cloudflare D1 の最小互換APIを再現(prepare/bind/first/all/run/batch)
import { DatabaseSync } from "node:sqlite";

export function createD1(schemaSql) {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(schemaSql);
  const isRead = (sql) => /^\s*(select|with)\b/i.test(sql) || /\breturning\b/i.test(sql);
  class Stmt {
    constructor(sql, params = []) { this.sql = sql; this.params = params; }
    bind(...p) { return new Stmt(this.sql, p.map((v) => (v === undefined ? null : v))); }
    _exec(mode) {
      const st = db.prepare(this.sql);
      if (mode === "first") { const r = st.get(...this.params); return r ? { ...r } : null; }
      if (mode === "all") return { results: st.all(...this.params).map((r) => ({ ...r })), meta: { changes: 0 }, success: true };
      const r = st.run(...this.params);
      return { results: [], meta: { changes: Number(r.changes) }, success: true };
    }
    async first() { return this._exec("first"); }
    async all() { return this._exec("all"); }
    async run() { return isRead(this.sql) ? this._exec("all") : this._exec("run"); }
    _batchExec() { return isRead(this.sql) ? this._exec("all") : this._exec("run"); }
  }
  return {
    raw: db,
    prepare: (sql) => new Stmt(sql),
    async batch(stmts) {
      db.exec("BEGIN");
      try {
        const out = stmts.map((s) => s._batchExec());
        db.exec("COMMIT");
        return out;
      } catch (e) { db.exec("ROLLBACK"); throw e; }
    },
  };
}
