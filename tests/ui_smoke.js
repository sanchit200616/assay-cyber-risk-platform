// Executes the real app.js against a live server with a minimal fake DOM. Not a visual test.
const vm = require("vm"), fs = require("fs"), path = require("path");
const [port, email, password, vendorId, asmId, role] = process.argv.slice(2);
class Node_ { constructor(t) { this.nodeType = t; this.children = []; } }
class Text extends Node_ { constructor(s) { super(3); this.data = s; } get textContent() { return this.data; } }
class El extends Node_ {
  constructor(tag) { super(1); this.tag = tag; this.attrs = {}; this.listeners = {}; this.dataset = {}; this.className = ""; this.value = ""; this.disabled = false; this.classList = { toggle() {} }; }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(e, f) { (this.listeners[e] = this.listeners[e] || []).push(f); }
  append(...k) { this.children.push(...k.map((x) => (typeof x === "string" ? new Text(x) : x))); }
  prepend(...k) { this.children.unshift(...k); }
  replaceChildren(...k) { this.children = k.flat(); }
  querySelector(sel) { const f = (n) => { for (const c of n.children) { if (c.tag === sel) return c; const r = c.children && f(c); if (r) return r; } return null; }; return f(this); }
  remove() {} click() {}
  get textContent() { return this.children.map((c) => c.textContent).join(" "); }
  set textContent(v) { this.children = [new Text(String(v))]; }
}
const root = new El("div");
const store = {};
const ctx = { console, setTimeout, URL: { createObjectURL: () => "blob:x" }, prompt: () => null, Promise, Date, Number, Object, Array, String, Error, JSON, Math,
  document: { getElementById: () => root, createElement: (t) => new El(t), createElementNS: (_, t) => new El(t), createTextNode: (s) => new Text(s), body: new El("body") },
  location: { hash: "" }, sessionStorage: { getItem: (k) => store[k] || null, setItem: (k, v) => { store[k] = v; }, removeItem: (k) => { delete store[k]; } },
  window: { addEventListener() {} },
  fetch: async (url, opts = {}) => {
    const res = await fetch(`http://127.0.0.1:${port}${url}`, opts); const buf = Buffer.from(await res.arrayBuffer());
    return { ok: res.ok, status: res.status, statusText: res.statusText, headers: { get: (k) => res.headers.get(k) }, json: async () => JSON.parse(buf.toString()), blob: async () => buf };
  } };
vm.createContext(ctx);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fail = (m) => { console.error("UI SMOKE FAIL:", m); process.exit(1); };
(async () => {
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../cyberrisk/web/app.js"), "utf8"), ctx);
  if (!/Sign in/.test(root.textContent)) fail("login view not rendered");
  const r = await fetch(`http://127.0.0.1:${port}/api/v1/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
  const token = (await r.json()).access_token; store.token = token;
  vm.runInContext(`state.token = ${JSON.stringify(token)}`, ctx);
  vm.runInContext("render()", ctx); await sleep(400);
  const routes = ["dashboard", "vendors", "intel", "rag", "workflows", "reports", "jobs", "audit", `vendor/${vendorId}`, `assessment/${asmId}`];
  const results = {};
  for (const route of routes) {
    ctx.location.hash = "#/" + route; vm.runInContext("render()", ctx); await sleep(500);
    results[route] = root.textContent;
  }
  const must = (route, re) => { if (!re.test(results[route])) fail(`${route}: expected ${re}; got: ${results[route].slice(0, 400)}`); };
  must("dashboard", /Risk distribution/); must("vendors", /Northwind Payments/); must("intel", /login\.northwind-payments\.example/);
  must("rag", /Search/); must("workflows", /No remediation tasks|todo/);
  must(`vendor/${vendorId}`, /Correlated intelligence/); must(`assessment/${asmId}`, /Score and explanation/); must(`assessment/${asmId}`, /Integrity proof/);
  must(`assessment/${asmId}`, /What would change the risk level/);
  if (role === "admin") { must("audit", /Verify chain/); must("jobs", /Run pending now/); must("assessment/" + asmId, /Run risk assessment/); }
  if (role === "analyst") {
    if (/Audit ledger/.test(results["dashboard"])) fail("analyst nav shows Audit ledger");
    if (/Run risk assessment/.test(results[`assessment/${asmId}`])) fail("analyst sees run button");
    if (!/Permission denied/.test(results["audit"])) fail("analyst audit page should show permission-denied state");
  }
  for (const [k, v] of Object.entries(results)) if (/undefined|\[object/.test(v)) fail(`${k}: rendered 'undefined' or '[object'`);
  console.log(`UI smoke OK for ${role}: ${routes.length} routes rendered`);
  process.exit(0);
})().catch((e) => fail(e.stack));
