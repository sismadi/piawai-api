import { DatabaseSync } from 'node:sqlite';

class Stmt {
  constructor(db, sql, args = []) { this.db = db; this.sql = sql; this.args = args; }
  bind(...args) { return new Stmt(this.db, this.sql, args); }
  _prep() { return this.db.prepare(this.sql); }
  async first() { const r = this._prep().get(...this.args); return r === undefined ? null : r; }
  async all() { return { results: this._prep().all(...this.args) }; }
  async run() { this._prep().run(...this.args); return { success: true }; }
}

export function makeD1(schemaSql) {
  const db = new DatabaseSync(':memory:');
  if (schemaSql) db.exec(schemaSql);
  return {
    _raw: db,
    prepare(sql) { return new Stmt(db, sql); },
    async batch(stmts) { for (const s of stmts) await s.run(); return []; },
  };
}
