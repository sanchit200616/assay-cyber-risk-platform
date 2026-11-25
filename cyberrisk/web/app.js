"use strict";
/* Assay UI. All dynamic data is inserted via textContent/DOM nodes, never by injecting HTML strings. */
const API = "/api/v1";
const FACTORS = ["vulnerability", "threat", "exposure", "compliance", "investigation"];
const state = { token: sessionStorage.getItem("token"), me: null };
const root = document.getElementById("app");

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
const S = (tag, attrs, ...kids) => {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
};
const fmt = (n) => (n == null ? "n/a" : Number(n).toFixed(2));
const can = (p) => state.me && state.me.permissions.includes(p);
const badge = (lv) => h("span", { class: `badge lv-${lv || "Unscored"}` }, lv || "Unscored");
const sev = (s) => h("span", { class: `sev-${s}` }, s);

async function api(method, path, body) {
  const res = await fetch(API + path, { method, headers: { "Content-Type": "application/json", ...(state.token ? { Authorization: "Bearer " + state.token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const ct = res.headers.get("Content-Type") || "";
  const data = ct.includes("json") ? await res.json() : await res.blob();
  if (res.status === 401 && state.me) { logout(); throw new Error("Session expired"); }
  if (!res.ok) { const e = new Error(data.error ? data.error.message : res.statusText); e.status = res.status; e.details = data.error && data.error.details; e.cid = data.error && data.error.correlation_id; throw e; }
  return data;
}
function logout() { sessionStorage.removeItem("token"); state.token = null; state.me = null; render(); }

function loading() { return h("p", { class: "state", role: "status" }, "Loading…"); }
function errorBox(e) {
  if (e.status === 403) return h("p", { class: "state deny", role: "alert" }, "Permission denied: " + e.message + ". Your role cannot view or change this.");
  const det = e.details ? " " + Object.entries(e.details).map(([k, v]) => `${k}: ${v}`).join("; ") : "";
  return h("p", { class: "state err", role: "alert" }, `Error: ${e.message}${det}` + (e.cid ? ` (correlation ${e.cid})` : ""));
}
function empty(msg) { return h("p", { class: "state" }, msg); }
function table(head, rows) { return h("div", { class: "scroll" }, h("table", null, h("thead", null, h("tr", null, head.map((x) => h("th", null, x)))), h("tbody", null, rows.map((r) => h("tr", null, r.map((c) => h("td", null, c))))))); }
async function view(container, fn) {
  container.replaceChildren(loading());
  try { const node = await fn(); container.replaceChildren(node); } catch (e) { container.replaceChildren(errorBox(e)); }
}
function formRow(fields, submitLabel, onSubmit) {
  const inputs = {};
  const form = h("form", { class: "row" }, fields.map((f) => {
    const el = f.options ? h("select", { name: f.name, required: f.req !== false }, f.options.map((o) => h("option", { value: o }, o))) :
      f.area ? h("textarea", { name: f.name, rows: 3, cols: 36, required: f.req !== false }) :
      h("input", { name: f.name, type: f.type || "text", required: f.req !== false, placeholder: f.ph, value: f.value, step: f.step, min: f.min, max: f.max, size: f.size || 18 });
    inputs[f.name] = el; return h("label", null, f.label, el);
  }), h("button", { type: "submit" }, submitLabel));
  const msg = h("span", { class: "muted", role: "status" });
  form.append(msg);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault(); const vals = {}; for (const [k, el] of Object.entries(inputs)) vals[k] = el.value;
    const btn = form.querySelector("button"); btn.disabled = true; msg.textContent = "Working…";
    try { await onSubmit(vals); msg.textContent = ""; } catch (e) { msg.replaceChildren(errorBox(e)); } finally { btn.disabled = false; }
  });
  return form;
}

/* ------------------------------------------------------------ the Assay scale */
function assayScale(result, policyBands) {
  const W = 720, X0 = 10, SC = (W - 20) / 100, bands = policyBands;
  const svg = S("svg", { class: "assay", viewBox: `0 0 ${W} 190`, role: "img", "aria-label": `Risk score ${fmt(result.score)} of 100, level ${result.level}. Factor contributions are shown as labelled segments.` });
  bands.forEach(([name, lo], i) => {
    const hi = i + 1 < bands.length ? bands[i + 1][1] : 100;
    svg.append(S("rect", { x: X0 + lo * SC, y: 30, width: (hi - lo) * SC, height: 22, fill: "none", stroke: "var(--rule)" }),
      S("text", { x: X0 + lo * SC + 4, y: 45, class: "m" }, `${name} ${lo}–${hi}`));
  });
  let acc = 0; const colors = ["--f1", "--f2", "--f3", "--f4", "--f5"];
  result.factors.filter((f) => f.present).forEach((f) => {
    const x = X0 + acc * SC, w = f.contribution * SC, idx = FACTORS.indexOf(f.factor);
    svg.append(S("rect", { x, y: 62, width: Math.max(w, 1), height: 30, fill: `var(${colors[idx]})` }), S("title", {}, `${f.factor}: contributes ${fmt(f.contribution)}`));
    if (w > 46) svg.append(S("text", { x: x + 4, y: 82, fill: "#fff", style: "fill:#fff;font-weight:600" }, f.factor.slice(0, Math.floor(w / 7))));
    acc += f.contribution;
  });
  const nx = X0 + result.score * SC;
  svg.append(S("line", { x1: nx, x2: nx, y1: 22, y2: 102, stroke: "var(--ink)", "stroke-width": 3 }), S("text", { x: Math.min(Math.max(nx - 40, 4), W - 130), y: 16, style: "font-weight:700;font-size:14px" }, `Score ${fmt(result.score)} · ${result.level}`));
  const bound = bands.find((b) => b[0] === result.level);
  if (bound && bound[1] > 0) {
    const bx = X0 + bound[1] * SC;
    svg.append(S("line", { x1: bx, x2: bx, y1: 52, y2: 118, stroke: "var(--ok)", "stroke-width": 2, "stroke-dasharray": "4 3" }),
      S("text", { x: bx - 4, y: 132, "text-anchor": "end", style: "fill:var(--ok);font-weight:600" }, `Below ${bound[1]} the level drops to ${(bands[bands.indexOf(bound) - 1] || [""])[0]}`));
  }
  let lx = X0; FACTORS.forEach((f, i) => { svg.append(S("rect", { x: lx, y: 150, width: 12, height: 12, fill: `var(${colors[i]})` }), S("text", { x: lx + 17, y: 161 }, f)); lx += 135; });
  return svg;
}
const BANDS = [["Minimal", 0], ["Low", 20], ["Medium", 40], ["High", 60], ["Critical", 80]];

/* ------------------------------------------------------------ pages */
const pages = {};
pages.dashboard = () => { const el = page("Dashboard"); view(el, async () => {
  const d = await api("GET", "/dashboard");
  const levels = ["Critical", "High", "Medium", "Low", "Minimal", "Unscored"];
  return h("div", null, h("div", { class: "grid" }, [["Vendors", d.vendors], ["Assessments", d.assessments], ["Open workflows", d.open_workflows], ["Jobs queued", d.jobs.queued], ["Jobs failed", d.jobs.failed]].map(([l, v]) => h("div", { class: "stat" }, h("b", null, v), h("span", null, l)))),
    h("h2", null, "Risk distribution"), table(["Level", "Assessments"], levels.map((l) => [badge(l), d.by_level[l] || 0])),
    h("h2", null, "Open findings by severity"), Object.keys(d.open_findings).length ? table(["Severity", "Open"], Object.entries(d.open_findings).map(([k, v]) => [sev(k), v])) : empty("No open findings."),
    h("h2", null, "Recent activity"), d.recent_activity.length ? table(["Time", "Action", "Outcome"], d.recent_activity.map((a) => [a.ts, a.action, a.outcome])) : empty("No activity yet."));
}); return el; };

pages.vendors = () => { const el = page("Vendors"); view(el, async () => {
  const { items } = await api("GET", "/vendors");
  const wrap = h("div", null);
  if (can("vendors.write")) wrap.append(h("div", { class: "card" }, h("h3", null, "Register vendor"), formRow([{ name: "name", label: "Name" }, { name: "category", label: "Category" }, { name: "domain", label: "Domain", ph: "vendor.example" }, { name: "criticality", label: "Criticality", options: ["low", "medium", "high", "critical"] }], "Add vendor", async (v) => { await api("POST", "/vendors", { ...v, synthetic: false }); render(); })));
  wrap.append(items.length ? table(["Vendor", "Domain", "Criticality", "Latest score", "Level"], items.map((v) => [h("a", { href: `#/vendor/${v.id}` }, v.name, v.synthetic ? " (synthetic)" : ""), v.domain, v.criticality, fmt(v.latest_score), badge(v.latest_level)])) : empty("No vendors yet. Register one to begin."));
  return wrap; }); return el; };

pages.vendor = (id) => { const el = page(""); view(el, async () => {
  const v = await api("GET", `/vendors/${id}`); const wrap = h("div", null);
  wrap.append(h("h1", null, v.name), h("p", { class: "muted" }, `${v.category} · ${v.domain} · criticality ${v.criticality}`));
  wrap.append(h("h2", null, "Assets"), v.assets.length ? table(["Name", "Type", "Identifier", "Environment", "Exposure"], v.assets.map((a) => [a.name, a.type, h("span", { class: "mono" }, a.identifier), a.environment, a.exposure])) : empty("No assets registered."));
  if (can("assets.write")) wrap.append(h("div", { class: "card" }, formRow([{ name: "name", label: "Asset name" }, { name: "identifier", label: "Hostname or IP" }, { name: "type", label: "Type", options: ["host", "service", "application", "database", "other"] }, { name: "environment", label: "Environment", options: ["production", "staging", "development"] }, { name: "exposure", label: "Exposure", options: ["internal", "partner", "internet"] }], "Add asset", async (f) => { await api("POST", "/assets", { ...f, vendor_id: id }); render(); })));
  wrap.append(h("h2", null, "Assessments"), v.assessments.length ? table(["Title", "Status", "Score", "Level"], v.assessments.map((a) => [h("a", { href: `#/assessment/${a.id}` }, a.title), a.status, fmt(a.score), badge(a.level)])) : empty("No assessments yet."));
  if (can("assessments.write")) wrap.append(h("div", { class: "card" }, formRow([{ name: "title", label: "New assessment title", size: 30 }], "Create assessment", async (f) => { const a = await api("POST", "/assessments", { vendor_id: id, title: f.title }); location.hash = `#/assessment/${a.id}`; })));
  const intel = can("intel.read") ? await api("GET", `/vendors/${id}/intelligence`) : { items: [] };
  wrap.append(h("h2", null, "Correlated intelligence"), intel.items.length ? table(["Indicator", "Type", "Why it matches", "Sources", "Confidence", "Severity"], intel.items.map((i) => [h("span", { class: "mono" }, i.value), i.type, i.match_reason, i.source_count, fmt(i.corroborated_confidence), sev(i.max_severity)])) : empty("No collected intelligence matches this vendor. Load the sample feed on the Intelligence page."));
  return wrap; }); return el; };

pages.assessment = (id) => { const el = page(""); const load = () => view(el, async () => {
  const a = await api("GET", `/assessments/${id}`); const wrap = h("div", null);
  wrap.append(h("h1", null, a.title), h("p", { class: "muted" }, h("a", { href: `#/vendor/${a.vendor_id}` }, a.vendor_name), ` · status ${a.status}`));
  const bar = h("div", { class: "row", style: "display:flex;gap:.5rem;flex-wrap:wrap" });
  const msg = h("span", { role: "status", class: "muted" });
  const act = (label, fn, alt) => h("button", { class: alt ? "alt" : "", onclick: async (ev) => { ev.target.disabled = true; msg.textContent = "Working…"; try { await fn(); } catch (e) { msg.replaceChildren(errorBox(e)); ev.target.disabled = false; } } }, label);
  if (can("assessments.run")) bar.append(act("Run risk assessment", async () => { await api("POST", `/assessments/${id}/run`); load(); }));
  if (can("reports.write")) { bar.append(act("Generate Markdown report", async () => { await api("POST", "/reports", { assessment_id: id, format: "markdown" }); msg.textContent = "Report created: see Reports."; }, true), act("Generate HTML report", async () => { await api("POST", "/reports", { assessment_id: id, format: "html" }); msg.textContent = "Report created: see Reports."; }, true)); }
  bar.append(msg); wrap.append(bar);
  const L = a.latest;
  if (!L) wrap.append(empty("Not yet assessed. Add findings, then run the risk assessment."));
  else {
    const r = L.result;
    wrap.append(h("h2", null, "Score and explanation"), h("p", null, badge(r.level), ` ${fmt(r.score)} / 100 · status ${r.status} · coverage ${(r.coverage * 100).toFixed(0)}% · evidence trust ${r.trust.toFixed(2)} · policy v${r.policy_version} · as of ${r.as_of}`));
    if (r.score != null) wrap.append(assayScale(r, BANDS));
    if (r.warnings.length) wrap.append(h("div", { class: "card" }, h("h3", null, "Warnings"), h("ul", null, r.warnings.map((w) => h("li", null, w.message)))));
    wrap.append(table(["Factor", "Score", "Weight", "Effective", "Contribution", "Why"], r.factors.map((f) => [f.factor, fmt(f.score), f.weight, f.effective_weight, fmt(f.contribution), f.rationale])));
    const cf = r.counterfactuals;
    wrap.append(h("h2", null, "What would change the risk level"));
    wrap.append(cf.level_drop.length ? table(["Factor", "Now", "Needed to drop a level", "Reduction", "Achievable alone"], cf.level_drop.map((c) => [c.factor, c.current, fmt(c.required_score), fmt(c.reduction), c.feasible ? "yes" : "no"])) : empty("Already at the lowest level."));
    if (cf.remediation.length) wrap.append(h("h3", null, "Highest-impact fixes (simulated by resolving each)"), table(["Evidence", "Severity", "Score if fixed", "Change", "Level then"], cf.remediation.map((c) => [c.title, sev(c.severity), fmt(c.score_if_resolved), "-" + fmt(c.delta), badge(c.level_if_resolved)])));
    wrap.append(h("h2", null, "Evidence considered"), table(["ID", "Factor", "Severity", "Conf.", "Observed", "Source", "Title"], L.snapshot.map((s) => [h("span", { class: "mono" }, s.id), s.factor, sev(s.severity), s.confidence.toFixed(2), s.observed_at, s.source, s.title + (s.resolved ? " (resolved)" : "")])));
    const proof = h("div", { class: "proof" }, h("h3", null, "Integrity proof"), h("p", { class: "mono" }, "policy hash: " + r.policy_hash), h("p", { class: "mono" }, "result hash: " + L.result_hash), h("p", { class: "muted" }, `Recorded in audit ledger entry #${a.runs[0].ledger_seq}.`));
    const out = h("p", { role: "status" });
    proof.append(h("button", { onclick: async () => { out.textContent = "Re-scoring from stored evidence…"; try { const v = await api("GET", `/assessments/${id}/verify`); proof.classList.toggle("bad", !v.ok); out.textContent = v.ok ? "VERIFIED: recomputed hash matches, policy hash matches, ledger entry matches and the ledger chain is intact." : `FAILED: hash match ${v.hash_match}, policy ${v.policy_hash_match}, ledger entry ${v.ledger_entry_match}, chain ${v.ledger_chain_ok}.`; } catch (e) { out.replaceChildren(errorBox(e)); } } }, "Re-verify by replay"), out);
    wrap.append(proof);
  }
  wrap.append(h("h2", null, "Findings"));
  wrap.append(a.findings.length ? table(["Finding", "Factor", "Severity", "Conf.", "Source", "Evidence", "Status", ""], a.findings.map((f) => [f.title + (f.cve_id ? ` (${f.cve_id})` : ""), f.factor, sev(f.severity), f.confidence, f.source, f.evidence_count,
    can("findings.write") ? h("select", { "aria-label": "Status", onchange: async (ev) => { try { await api("PATCH", `/findings/${f.id}`, { status: ev.target.value }); load(); } catch (e) { msg.replaceChildren(errorBox(e)); ev.target.value = f.status; } } }, ["open", "in_progress", "accepted", "resolved"].map((s) => h("option", { value: s, selected: s === f.status }, s))) : f.status,
    can("workflows.write") ? h("button", { class: "alt", onclick: async () => { await api("POST", "/workflows", { assessment_id: id, finding_id: f.id, title: "Remediate: " + f.title }); msg.textContent = "Workflow created: see Workflows."; } }, "Create task") : ""])) : empty("No findings yet."));
  if (can("findings.write")) {
    wrap.append(h("div", { class: "card" }, h("h3", null, "Add finding"), formRow([{ name: "title", label: "Title", size: 28 }, { name: "factor", label: "Factor", options: FACTORS }, { name: "severity", label: "Severity", options: ["none", "info", "low", "medium", "high", "critical"] }, { name: "confidence", label: "Confidence 0–1", type: "number", step: "0.05", min: "0", max: "1", value: "0.7" }, { name: "source", label: "Source", value: "manual review" }, { name: "cve_id", label: "CVE (optional)", req: false, ph: "CVE-2099-10001" }], "Add finding", async (f) => { const body = { ...f, confidence: Number(f.confidence), observed_at: new Date().toISOString() }; if (!body.cve_id) delete body.cve_id; await api("POST", `/assessments/${id}/findings`, body); load(); })));
    if (a.findings.length) wrap.append(h("div", { class: "card" }, h("h3", null, "Attach evidence to a finding"), formRow([{ name: "finding_id", label: "Finding", options: a.findings.map((f) => f.id) }, { name: "source", label: "Source", value: "scanner export" }, { name: "content", label: "Content (hashed with SHA-256)", area: true }, { name: "confidence", label: "Confidence", type: "number", step: "0.05", min: "0", max: "1", value: "0.7" }], "Attach", async (f) => { await api("POST", "/evidence", { ...f, confidence: Number(f.confidence), observed_at: new Date().toISOString() }); load(); })));
  }
  return wrap; }); load(); return el; };

pages.intel = () => { const el = page("Intelligence"); const load = () => view(el, async () => {
  const wrap = h("div", null, h("p", { class: "muted" }, "Signals are normalised (defanged and mixed-case spellings converge), deduplicated per indicator, and every source observation keeps its provenance. Intelligence is evidence, not a verdict."));
  if (can("intel.collect")) wrap.append(h("button", { onclick: async (ev) => { ev.target.disabled = true; try { const r = await api("POST", "/intelligence/collect", { source: "sample" }); wrap.prepend(h("p", { role: "status" }, `Loaded SYNTHETIC sample feed: ${r.new_signals} new, ${r.duplicates_ignored} duplicates ignored, ${r.errors.length} rejected.`)); load(); } catch (e) { wrap.prepend(errorBox(e)); ev.target.disabled = false; } } }, "Load synthetic sample feed"));
  const { items } = await api("GET", "/intelligence/signals");
  wrap.append(items.length ? table(["Indicator", "Type", "Sources", "Corroborated confidence", "Max severity", "Last seen", "Provenance"], items.map((i) => [h("span", { class: "mono" }, i.value), i.type, i.source_count, fmt(i.corroborated_confidence), sev(i.max_severity), i.last_seen,
    i.signals.map((s) => h("div", { class: "muted" }, `${s.source} #${s.source_record_id} (${s.confidence}) as "${s.original_value}"` + (s.synthetic ? " [synthetic]" : "")))])) : empty("No intelligence collected yet."));
  return wrap; }); load(); return el; };

pages.rag = () => { const el = page("Evidence search"); const out = h("div", null);
  el.append(h("p", { class: "muted" }, "Retrieval over the document corpus. Passages are untrusted text and never influence the score. The built-in embedder is lexical (development adapter), not semantic."),
    formRow([{ name: "question", label: "Question", size: 52, ph: "How fast must exploited critical vulnerabilities be patched?" }], "Search", async (f) => {
      out.replaceChildren(loading()); const r = await api("POST", "/rag/query", { question: f.question, top_k: 4 });
      out.replaceChildren(r.status !== "ok" ? h("p", { class: "state" }, "No evidence found. " + r.reason) : r.passages.map((p) => h("div", { class: "passage" + (p.injection_suspected ? " flag" : "") }, h("p", null, p.text), h("p", { class: "muted mono" }, `${p.citation.title} · chunk ${p.citation.chunk_id} · source ${p.citation.source}${p.citation.synthetic ? " [synthetic]" : ""} · score ${p.score}`), p.injection_suspected ? h("p", { class: "sev-high" }, "Warning: this passage contains instruction-like text and is treated as untrusted data.") : null)));
    }), out); return el; };

pages.workflows = () => { const el = page("Workflows"); const load = () => view(el, async () => {
  const { items } = await api("GET", "/workflows"); const cols = ["todo", "doing", "blocked", "done"];
  if (!items.length) return empty("No remediation tasks. Create one from a finding on an assessment page.");
  const next = { todo: ["doing", "blocked"], doing: ["done", "blocked", "todo"], blocked: ["todo", "doing"], done: ["doing"] };
  return h("div", { class: "board" }, cols.map((c) => h("section", { class: "col", "aria-label": c }, h("h3", null, `${c} (${items.filter((w) => w.status === c).length})`), items.filter((w) => w.status === c).map((w) => h("div", { class: "ticket" }, h("div", null, w.title), h("div", { class: "muted" }, "owner: " + (w.owner || "unassigned")),
    can("workflows.write") ? h("div", null, next[c].map((n) => h("button", { class: "alt", style: "margin:.2rem .2rem 0 0", onclick: async () => { await api("PATCH", `/workflows/${w.id}`, { status: n }); load(); } }, "→ " + n)), h("button", { class: "alt", onclick: async () => { const o = prompt("Owner"); if (o) { await api("PATCH", `/workflows/${w.id}`, { owner: o }); load(); } } }, "assign")) : null)))));
  }); load(); return el; };

pages.reports = () => { const el = page("Reports"); view(el, async () => {
  const { items } = await api("GET", "/reports");
  return items.length ? table(["Report", "Assessment", "Format", "Generated", "Content hash", ""], items.map((r) => [h("span", { class: "mono" }, r.id), h("a", { href: `#/assessment/${r.assessment_id}` }, "open"), r.format, r.generated_at, h("span", { class: "mono" }, r.content_hash.slice(0, 16) + "…"),
    h("button", { class: "alt", onclick: async () => { const b = await api("GET", `/reports/${r.id}/download`); const a = h("a", { href: URL.createObjectURL(b), download: `risk-report-${r.id}.${r.format === "html" ? "html" : "md"}` }); document.body.append(a); a.click(); a.remove(); } }, "Download")])) : empty("No reports yet. Generate one from an assessment.");
  }); return el; };

pages.jobs = () => { const el = page("Background jobs"); const load = () => view(el, async () => {
  const d = await api("GET", "/jobs"); const wrap = h("div", null, h("p", null, `queued ${d.stats.queued} · running ${d.stats.running} · succeeded ${d.stats.succeeded} · failed ${d.stats.failed}`));
  if (can("jobs.run")) wrap.append(h("button", { onclick: async () => { await api("POST", "/jobs/run-pending"); load(); } }, "Run pending now"));
  wrap.append(d.items.length ? table(["Job", "Type", "Status", "Attempts", "Error", "Correlation"], d.items.map((j) => [h("span", { class: "mono" }, j.id), j.type, j.status, `${j.attempts}/${j.max_attempts}`, j.last_error || "", h("span", { class: "mono" }, j.correlation_id || "")])) : empty("No jobs yet. Run an assessment or report with ?async=1."));
  return wrap; }); load(); return el; };

pages.audit = () => { const el = page("Audit ledger"); const load = () => view(el, async () => {
  const d = await api("GET", "/audit?limit=100"); const wrap = h("div", null); const out = h("p", { role: "status" });
  wrap.append(h("p", { class: "muted" }, "Hash-chained and append-only. Head: ", h("span", { class: "mono" }, `#${d.head.seq} ${d.head.hash}`)),
    h("button", { onclick: async () => { const v = await api("GET", "/audit/verify"); out.textContent = v.ok ? `Chain intact: ${v.checked} entries verified.` : `TAMPERING DETECTED at entry #${v.first_bad_seq}.`; out.className = v.ok ? "" : "sev-high"; } }, "Verify chain"), out,
    table(["#", "Time", "Actor", "Action", "Target", "Outcome", "Correlation"], d.items.map((e) => [e.seq, e.ts, e.actor, e.action, h("span", { class: "mono" }, e.target), e.outcome, h("span", { class: "mono" }, e.correlation_id)])));
  return wrap; }); load(); return el; };

/* ------------------------------------------------------------ shell */
function page(title) { const el = h("div", null); el.dataset.title = title; return el; }
const NAV = [["dashboard", "Dashboard", "dashboard.read"], ["vendors", "Vendors", "vendors.read"], ["intel", "Intelligence", "intel.read"], ["rag", "Evidence search", "rag.query"], ["workflows", "Workflows", "workflows.read"], ["reports", "Reports", "reports.read"], ["jobs", "Jobs", "jobs.read"], ["audit", "Audit ledger", "audit.read"]];

function render() {
  if (!state.token) return renderLogin();
  if (!state.me) { api("GET", "/me").then((m) => { state.me = m; render(); }).catch(() => logout()); root.replaceChildren(loading()); return; }
  const route = (location.hash || "#/dashboard").slice(2).split("/"); const [name, arg] = route;
  const key = pages[name] ? name : "dashboard";
  const content = h("main", { id: "main", tabindex: "-1" }, h("p", { class: "banner" }, "Demo data is synthetic: vendors, indicators (.example domains, documentation IPs, CVE-2099-*) and guidance documents were generated for demonstration. Nothing here is live threat intelligence."));
  const body = pages[key](arg); content.append(body.dataset && body.dataset.title ? h("h1", null, body.dataset.title) : "", body);
  root.replaceChildren(h("div", { class: "shell" }, h("nav", { class: "rail", "aria-label": "Primary" }, h("div", { class: "brand" }, "Assay"), h("div", { class: "tag" }, "explainable cyber risk"),
    NAV.filter((n) => can(n[2])).map(([k, label]) => h("a", { href: `#/${k}`, "aria-current": (key === k || (key === "vendor" && k === "vendors") || (key === "assessment" && k === "vendors")) ? "page" : null }, label)),
    h("div", { class: "who" }, `${state.me.email} (${state.me.role})`, h("br"), h("button", { class: "alt", onclick: logout }, "Sign out"))), content));
}
function renderLogin() {
  const msg = h("p", { role: "alert", class: "sev-high" });
  root.replaceChildren(h("div", { class: "login" }, h("h1", null, "Assay"), h("p", { class: "muted" }, "Sign in to the cyber risk workspace."),
    formRow([{ name: "email", label: "Email", type: "email", size: 30 }, { name: "password", label: "Password", type: "password", size: 30 }], "Sign in", async (f) => { try { const r = await api("POST", "/auth/login", f); state.token = r.access_token; sessionStorage.setItem("token", r.access_token); render(); } catch (e) { msg.textContent = e.message; } }), msg));
}
window.addEventListener("hashchange", render);
render();
