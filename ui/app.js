// Review UI. SECURITY: every value from the API (names, titles, URLs, evidence, raw traffic)
// is attacker- or user-controlled. Only textContent / value are used to render it: never
// the HTML-injecting DOM APIs (a test enforces this). Inline styles are blocked by the page's
// CSP, so colors are applied through the CSSOM (style.setProperty), which is allowed.
"use strict";

const $ = (id) => document.getElementById(id);
const SEV = ["critical", "high", "medium", "low", "info"];
const state = {
  token: sessionStorage.getItem("token") || "", authFailed: false,
  engagement: null, engagements: [], editing: null, deleting: null,
  findings: [], visible: [], selected: null, openGroups: new Set(),
  job: null, activeJob: null, queue: 0,
  wstgFilter: null, cov: null, covOpen: new Set(),
};
let tickTimer = null, lastSeenNew = -1, lastSeenStatus = "";
const readOnly = () => state.engagement?.status === "archived";
const kindLabel = (k) => (k === "bounty" ? "Bug bounty" : "Web app pentest");

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) n.append(kid);
  return n;
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  if (state.token) headers.Authorization = "Bearer " + state.token;
  // Every data call is tied to the selected engagement; only these are engagement-independent.
  if (state.engagement && !/^\/(engagements|status|health|logs|scan\/[^/]+\/(pause|resume|cancel))/.test(path))
    headers["X-Engagement"] = state.engagement.id;
  const res = await fetch("/api" + path, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
  if (res.status === 401) {
    state.authFailed = true;
    if (!$("dlg-token").open) $("dlg-token").showModal();
    throw new Error("Unauthorized: set the API token");
  }
  if (!res.ok) {
    let detail = await res.text();
    try { detail = JSON.parse(detail).detail ?? detail; } catch { /* plain text */ }
    throw new Error((typeof detail === "string" ? detail : JSON.stringify(detail)).slice(0, 300));
  }
  return res.headers.get("content-type")?.includes("json") ? res.json() : res.text();
}

const badge = (text, cls) => el("span", { class: `badge ${cls || ""}`, text });
const sevBadge = (s) => badge(s, "sev-" + s);
const trunc = (s, n) => (s && s.length > n ? s.slice(0, n) + "\n… [truncated]" : s || "");
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "engagement";

function ago(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}
// A stable color per engagement: the swatch, header bar and cards all use it, so it is hard to
// confuse which client you are working in.
function accent(id) {
  let h = 0;
  for (const c of id) h = (h * 31 + c.charCodeAt(0)) % 360;
  return `hsl(${h} 62% 52%)`;
}

// ============================================================== views
function setView(name) {
  const review = name === "review";
  $("view-engagements").hidden = review;
  $("view-review").hidden = !review;
  $("btn-switch").hidden = !review;
  $("title").hidden = review;
  $("view-coverage").hidden = true;
  $("btn-wstg").hidden = !review;
  $("btn-wstg").textContent = "WSTG coverage";
  $("btn-scan").hidden = !review || readOnly();
  $("btn-report").hidden = !review;
  $("ro-badge").hidden = !(review && readOnly());
  $("kind-badge").hidden = !review;
  if (review && state.engagement) $("kind-badge").textContent = kindLabel(state.engagement.kind);
  if (!review) { $("stats").replaceChildren(); document.documentElement.style.removeProperty("--eng"); }
}

// ======================================================= engagements
async function showEngagements() {
  $("dlg-scan").close();
  state.engagement = null;
  state.job = null;
  setView("picker");
  $("eng-msg").hidden = true;
  await refreshPicker();
}

async function refreshPicker() {
  const data = await api("/engagements");
  state.engagements = data.engagements;
  state.activeJob = data.active_job;
  renderCards();
  renderJob();
}

function renderCards() {
  const live = state.engagements.filter((e) => e.status !== "archived");
  const archived = state.engagements.filter((e) => e.status === "archived");
  $("eng-list").replaceChildren(...(live.length ? live.map(card)
    : [el("p", { class: "empty", text: "No engagements yet. Create one for your first client to get started." })]));
  $("eng-archived-wrap").hidden = !archived.length;
  $("eng-archived").replaceChildren(...archived.map(card));
}

function card(e) {
  const s = e.summary || { items: 0, by_status: {}, queue: 0 };
  const by = s.by_status || {};
  const counts = [["candidate", "to review"], ["confirmed", "confirmed"], ["reported", "reported"]]
    .filter(([k]) => by[k]).map(([k, label]) => `${by[k]} ${label}`);
  const archived = e.status === "archived";
  const lastUsed = localStorage.getItem("lastEngagement") === e.id && !archived;
  const art = el("article", { class: "card" + (archived ? " archived" : "") },
    el("div", { class: "card-top" },
      el("h3", { text: e.name }),
      badge(kindLabel(e.kind)),
      e.running ? badge("● scanning", "run") : null,
      archived ? badge("archived") : null,
      lastUsed ? badge("last used") : null),
    e.client ? el("div", { class: "muted", text: e.client }) : null,
    el("div", { class: "chips" },
      ...(e.scope.length ? e.scope.slice(0, 4).map((h) => el("span", { class: "chip", text: h }))
        : [el("span", { class: "chip warn", text: "no scope set" })]),
      e.scope.length > 4 ? el("span", { class: "chip", text: `+${e.scope.length - 4}` }) : null),
    el("div", { class: "muted", text: [`${s.items} requests`, ...counts, s.queue ? `${s.queue} awaiting model` : ""].filter(Boolean).join(" · ") }),
    el("div", { class: "muted small", text: e.last_opened ? "Opened " + ago(e.last_opened) : "Never opened" }),
    e.notes ? el("div", { class: "notes", text: e.notes.length > 140 ? e.notes.slice(0, 140) + "…" : e.notes }) : null,
    el("div", { class: "row" },
      el("button", { text: archived ? "Open (read-only)" : "Continue", onclick: () => openEngagement(e) }),
      archived ? null : el("button", { class: "ghost", text: "Edit", onclick: () => engDialog(e) }),
      el("button", { class: "ghost", text: archived ? "Restore" : "Archive", onclick: () => setArchived(e, !archived) }),
      el("button", { class: "danger", text: "Delete…", onclick: () => deleteDialog(e) })));
  art.style.setProperty("--eng", accent(e.id));
  return art;
}

async function openEngagement(e) {
  try { e = await api(`/engagements/${e.id}/open`, { method: "POST" }); } catch (err) { alert(err.message); return; }
  localStorage.setItem("lastEngagement", e.id);
  state.engagement = e;
  Object.assign(state, { findings: [], visible: [], selected: null, job: null, wstgFilter: null, cov: null });
  state.openGroups.clear();
  lastSeenNew = -1; lastSeenStatus = "";
  $("f-status").value = "candidate"; $("f-severity").value = ""; $("f-source").value = ""; $("f-search").value = "";
  document.documentElement.style.setProperty("--eng", accent(e.id));
  $("eng-name").textContent = e.name;
  $("detail").replaceChildren(el("p", { class: "empty", text: "Select a finding." }));
  setView("review");
  await load();
  kick();
}

async function setArchived(e, archive) {
  if (archive && !confirm(`Archive "${e.name}"?\nIt becomes read-only and moves out of the main list. Nothing is deleted, and you can restore it later.`)) return;
  try { await api(`/engagements/${e.id}`, { method: "PATCH", body: JSON.stringify({ status: archive ? "archived" : "active" }) }); }
  catch (err) { alert(err.message); }
  refreshPicker();
}

function engDialog(e) {
  state.editing = e;
  $("eng-title").textContent = e ? "Edit engagement" : "New engagement";
  $("eng-f-name").value = e ? e.name : "";
  $("eng-f-client").value = e ? e.client : "";
  // Deliberately NOT pre-filled for a new engagement: a scope copied from another client is how
  // out-of-scope testing happens.
  $("eng-f-scope").value = e ? e.scope.join("\n") : "";
  $("eng-f-notes").value = e ? e.notes : "";
  document.querySelectorAll("input[name=eng-kind]").forEach((r) => (r.checked = !!e && r.value === e.kind));
  $("eng-error").hidden = true;
  $("dlg-eng").showModal();
  $("eng-f-name").focus();
}
$("btn-new-eng").onclick = () => engDialog(null);
$("eng-save").onclick = async () => {
  const body = {
    name: $("eng-f-name").value.trim(),
    client: $("eng-f-client").value.trim(),
    scope: $("eng-f-scope").value.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean),
    notes: $("eng-f-notes").value,
  };
  body.kind = document.querySelector("input[name=eng-kind]:checked")?.value;
  if (!body.name) { $("eng-error").textContent = "Name is required."; $("eng-error").hidden = false; return; }
  if (!body.kind) { $("eng-error").textContent = "Choose the type of work: web app pentest or bug bounty."; $("eng-error").hidden = false; return; }
  try {
    if (state.editing) await api(`/engagements/${state.editing.id}`, { method: "PATCH", body: JSON.stringify(body) });
    else await api("/engagements", { method: "POST", body: JSON.stringify(body) });
    $("dlg-eng").close();
    await refreshPicker();
  } catch (err) { $("eng-error").textContent = err.message; $("eng-error").hidden = false; }
};

function deleteDialog(e) {
  state.deleting = e;
  $("del-name").textContent = e.name;
  $("del-input").value = "";
  $("del-go").disabled = true;
  $("del-error").hidden = true;
  $("dlg-delete").showModal();
}
$("del-input").addEventListener("input", () => { $("del-go").disabled = $("del-input").value !== state.deleting.name; });
$("del-go").onclick = async () => {
  try {
    await api(`/engagements/${state.deleting.id}`, { method: "DELETE", body: JSON.stringify({ confirm: $("del-input").value }) });
    if (localStorage.getItem("lastEngagement") === state.deleting.id) localStorage.removeItem("lastEngagement");
    $("dlg-delete").close();
    await refreshPicker();
  } catch (err) { $("del-error").textContent = err.message; $("del-error").hidden = false; }
};
$("btn-switch").onclick = () => showEngagements().catch((e) => { $("eng-msg").textContent = e.message; $("eng-msg").hidden = false; });

// ================================================================ list
async function load() {
  if (!state.engagement) return;
  const q = new URLSearchParams();
  for (const [id, key] of [["f-status", "status"], ["f-severity", "severity"], ["f-source", "source"]])
    if ($(id).value) q.set(key, $(id).value);
  if (state.wstgFilter) q.set("wstg", state.wstgFilter);
  renderWstgChip();
  try {
    const data = await api("/findings?" + q);
    state.findings = data.findings;
    render();
    loadStats();
  } catch (e) { $("list").replaceChildren(el("li", { class: "empty err", text: e.message })); }
}

function renderWstgChip() {
  const b = $("wstg-clear");
  b.hidden = !state.wstgFilter;
  if (state.wstgFilter) b.textContent = `WSTG-${state.wstgFilter} ✕`;
}
$("wstg-clear").onclick = () => { state.wstgFilter = null; load(); };

async function loadStats() {
  if (!state.engagement) return;
  try {
    const s = await api("/findings/stats");
    state.queue = s.model_queue || 0;
    const chips = [`${s.items_seen} items`, ...Object.entries(s.by_status || {}).map(([k, v]) => `${v} ${k}`)];
    if (state.queue) chips.push(`${state.queue} awaiting model`);
    $("stats").replaceChildren(...chips.map((c) => el("span", { class: "chip", text: c })));
  } catch { /* shown by load() */ }
}

function filtered() {
  const term = $("f-search").value.trim().toLowerCase();
  return state.findings.filter((f) => !term || (f.title + " " + (f.url || "")).toLowerCase().includes(term));
}

function render() {
  const items = filtered();
  state.visible = [];
  const list = $("list");
  list.replaceChildren();
  if (!items.length) { list.append(el("li", { class: "empty", text: "No findings match." })); return; }

  if (!$("f-group").checked) {
    items.forEach((f) => list.append(itemRow(f)));
    return;
  }
  const groups = new Map();
  for (const f of items) {
    const key = `${f.source}|${f.type}|${f.title}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  const ordered = [...groups.values()].sort((a, b) => SEV.indexOf(a[0].severity) - SEV.indexOf(b[0].severity));
  for (const g of ordered) {
    if (g.length === 1) { list.append(itemRow(g[0])); continue; }
    const gkey = `${g[0].source}|${g[0].type}|${g[0].title}`;
    const inner = el("ul");
    inner.hidden = !state.openGroups.has(gkey);
    g.forEach((f) => inner.append(itemRow(f)));
    const head = el("div", { class: "ghead", role: "button", tabindex: "0", "aria-expanded": String(!inner.hidden) },
      sevBadge(g[0].severity),
      el("div", { class: "t" }, el("b", { text: g[0].title }), el("small", { text: `${g[0].source} · ${g[0].type}` })),
      el("span", { class: "count", text: `×${g.length}` }));
    const toggle = () => {
      inner.hidden = !inner.hidden;
      head.setAttribute("aria-expanded", String(!inner.hidden));
      inner.hidden ? state.openGroups.delete(gkey) : state.openGroups.add(gkey);
    };
    head.addEventListener("click", toggle);
    head.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    if (!readOnly()) head.append(el("button", { class: "ghost", text: "Dismiss all", title: "Dismiss every finding in this group",
      onclick: async (e) => { e.stopPropagation(); await bulkStatus(g, "dismissed"); } }));
    list.append(el("li", { class: "group" }, head, inner));
  }
}

function itemRow(f) {
  state.visible.push(f);
  const li = el("li", { class: "item", role: "option", tabindex: "0", "data-id": f.id,
    "aria-selected": String(state.selected === f.id) },
    sevBadge(f.severity),
    el("div", { class: "t" }, el("b", { text: f.title }), el("small", { text: `${f.method || ""} ${f.url || ""}` })),
    f.evidence_quality === "weak" ? badge("weak", "weak") : null);
  li.addEventListener("click", () => select(f.id));
  li.addEventListener("keydown", (e) => { if (e.key === "Enter") select(f.id); });
  return li;
}

async function bulkStatus(group, status) {
  if (!confirm(`Mark ${group.length} findings as ${status}?`)) return;
  for (const f of group) await api(`/findings/${f.id}`, { method: "PATCH", body: JSON.stringify({ status }) });
  load();
}

// ============================================================== detail
async function select(id) {
  state.selected = id;
  document.querySelectorAll("#list [role=option]").forEach((n) => n.setAttribute("aria-selected", String(n.dataset.id === id)));
  const box = $("detail");
  try {
    const f = await api("/findings/" + id);
    box.replaceChildren(...detail(f).filter(Boolean));
  } catch (e) { box.replaceChildren(el("p", { class: "err", text: e.message })); }
}

function detail(f) {
  const ro = readOnly();
  const notes = el("textarea", { id: "notes", "aria-label": "Your notes", placeholder: "How you reproduced it, scope, caveats…" });
  notes.value = f.notes || "";
  const prose = el("textarea", { id: "prose", "aria-label": "Report text", placeholder: "Report prose (use Draft, then edit)" });
  prose.value = f.report_text || "";
  notes.readOnly = prose.readOnly = ro;
  const sev = el("select", { id: "sev", "aria-label": "Severity" }, ...SEV.map((s) => el("option", { value: s, text: s })));
  sev.value = f.severity;
  sev.disabled = ro;
  const status = (s) => async () => { await api("/findings/" + f.id, { method: "PATCH", body: JSON.stringify({ status: s }) }); await load(); next(); };
  const wtags = el("input", { id: "wstg-tags", type: "text", placeholder: "e.g. ATHZ-04, SESS-02", "aria-label": "WSTG test IDs" });
  wtags.value = (f.wstg || "").split(",").filter(Boolean).join(", ");
  wtags.readOnly = ro;
  const save = async (btn) => {
    try {
      await api("/findings/" + f.id, { method: "PATCH", body: JSON.stringify({
        notes: notes.value, severity: sev.value, report_text: prose.value,
        wstg: wtags.value.split(/[,\s]+/).filter(Boolean) }) });
    } catch (err) { alert(err.message); return; }
    btn.textContent = "Saved"; setTimeout(() => (btn.textContent = "Save notes"), 1200); load(); select(f.id);
  };
  const saveBtn = el("button", { text: "Save notes", class: "ghost", onclick: (e) => save(e.target) });
  const draftBtn = el("button", { text: "Draft with model", class: "ghost", onclick: async (e) => {
    e.target.disabled = true; e.target.textContent = "Drafting…";
    try { prose.value = (await api(`/findings/${f.id}/draft`, { method: "POST" })).report_text; }
    catch (err) { alert(err.message); }
    e.target.disabled = false; e.target.textContent = "Draft with model";
  } });

  const item = f.item;
  return [
    el("h2", { text: f.title }),
    el("div", { class: "meta" }, sevBadge(f.severity), badge("conf: " + f.confidence), badge(f.source), badge(f.type), badge(f.status),
      f.evidence_quality === "weak" ? badge("weak evidence", "weak") : null),
    el("div", { class: "mono", text: `${f.method || ""} ${f.url || ""}` }),
    field("OWASP WSTG v4.2", el("div", {},
      el("div", { class: "wtags" }, ...(f.wstg_labels || []).map((l) => {
        const b = badge("WSTG-" + l.id, "st-tested"); b.title = l.name; return b;
      }), (f.wstg_labels || []).length ? null : el("span", { class: "hint", text: "Not mapped to a test." })),
      wtags)),
    ro ? null : el("div", { class: "row" },
      el("button", { text: "Confirm (c)", onclick: status("confirmed") }),
      el("button", { text: "Dismiss (d)", class: "danger", onclick: status("dismissed") }),
      f.status !== "candidate" ? el("button", { text: "Back to candidate", class: "ghost", onclick: status("candidate") }) : null,
      f.status === "confirmed" ? el("button", { text: "Mark reported", class: "ghost", onclick: status("reported") }) : null,
      el("label", { class: "inline" }, "Severity ", sev)),
    f.evidence_quality === "weak" ? el("p", { class: "weak-note",
      text: "Weak evidence: the quoted text is thin on its own (for example a bare header, or a very short or request-only quote). Open the request and response below and confirm the problem exists before you rely on this." }) : null,
    f.source === "llm" ? field("Why the model flagged this (unverified reasoning)",
      el("div", { class: "reasoning", text: f.description || "The model gave no explanation." })) : null,
    field("Evidence", el("pre", { text: f.evidence || "(none)" })),
    contextBox(f),
    f.source === "llm" ? null : field("Why it matters", el("div", { text: f.description || "" })),
    field("Remediation", el("div", { text: f.recommendation || "" })),
    field("Your notes", notes),
    field("Report text", prose),
    ro ? null : el("div", { class: "row" }, saveBtn, draftBtn),
  ];
}

// Find the evidence quote inside a message. The model may have collapsed whitespace, so the
// match is whitespace-flexible and case-insensitive (the same leniency the quality gate uses).
function locate(text, quote) {
  const q = (quote || "").trim();
  if (!text || !q) return null;
  const exact = text.indexOf(q);
  if (exact >= 0) return [exact, exact + q.length];
  const pattern = q.split(/\s+/).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\s+");
  const m = new RegExp(pattern, "i").exec(text);
  return m ? [m.index, m.index + m[0].length] : null;
}

const CONTEXT_CHARS = 6000;
// One message (request or response) with the evidence highlighted. Long bodies show a window
// around the match; "Show all" swaps in the full text. Everything goes in as text nodes.
function trafficPane(label, text, quote) {
  const full = text || "";
  const hit = locate(full, quote);
  const pre = el("pre", { class: "traffic" });
  const head = el("div", { class: "traffic-head" }, el("span", { class: "label", text: label }),
    hit ? badge("evidence highlighted", "ok") : badge(full ? "evidence not in this message" : "empty", ""));
  let showAll = false;
  const paint = () => {
    pre.replaceChildren();
    let a = 0, b = full.length;
    if (!showAll && full.length > CONTEXT_CHARS) {
      const mid = hit ? Math.floor((hit[0] + hit[1]) / 2) : 0;
      a = Math.max(0, Math.min(mid - CONTEXT_CHARS / 2, full.length - CONTEXT_CHARS));
      b = Math.min(full.length, a + CONTEXT_CHARS);
    }
    if (a > 0) pre.append("… [earlier text hidden]\n");
    if (hit && hit[0] >= a && hit[1] <= b) {
      pre.append(full.slice(a, hit[0]), el("mark", { text: full.slice(hit[0], hit[1]) }), full.slice(hit[1], b));
    } else pre.append(full.slice(a, b) || "(empty)");
    if (b < full.length) pre.append("\n… [later text hidden]");
  };
  paint();
  const more = full.length > CONTEXT_CHARS
    ? el("button", { class: "ghost", text: `Show all (${full.length.toLocaleString()} chars)`, onclick: (e) => {
        showAll = !showAll; paint(); e.target.textContent = showAll ? "Show less" : `Show all (${full.length.toLocaleString()} chars)`;
      } }) : null;
  return el("div", { class: "traffic-pane" }, head, pre, more);
}

function contextBox(f) {
  const item = f.item;
  if (!item) return el("p", { class: "hint", text: "The original request and response are not stored for this finding." });
  return el("details", { class: "context" }, el("summary", { text: "Show in context: full request and response" }),
    trafficPane("Request", item.raw_request, f.evidence),
    trafficPane("Response", item.raw_response, f.evidence));
}

function field(label, node) { return el("div", { class: "field" }, el("span", { class: "label", text: label }), node); }

function move(delta) {
  const i = state.visible.findIndex((f) => f.id === state.selected);
  const n = state.visible[Math.min(Math.max(i + delta, 0), state.visible.length - 1)];
  if (n) { select(n.id); document.querySelector(`[data-id="${n.id}"]`)?.scrollIntoView({ block: "nearest" }); }
}
function next() { if (state.visible.length) move(0); else $("detail").replaceChildren(el("p", { class: "empty", text: "Select a finding." })); }

document.addEventListener("keydown", (e) => {
  if ($("view-review").hidden || readOnly() || [...document.querySelectorAll("dialog[open]")].some((d) => d.id !== "dlg-scan")) return;
  if (e.target.closest("input, textarea, select") || e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === "j") move(1);
  else if (e.key === "k") move(-1);
  else if ((e.key === "c" || e.key === "d") && state.selected) {
    api("/findings/" + state.selected, { method: "PATCH", body: JSON.stringify({ status: e.key === "c" ? "confirmed" : "dismissed" }) })
      .then(load).then(() => move(0)).catch((err) => alert(err.message));
  }
});

// ================================================================ scan
// One job at a time across ALL engagements (there is one model). A single poller keeps the
// header chip, the scan dialog and the findings list in step.
const mode = () => document.querySelector("input[name=scan-mode]:checked").value;
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleTimeString() : "never");
const jobKey = (j) => (j ? `${j.id}|${j.status}|${j.paused}` : "");
const isActive = (j) => !!j && (j.status === "running" || j.status === "paused");

function describe(j) {
  const stateText = j.status === "running" && j.paused ? "pausing (finishing current item)…"
    : j.status === "paused" ? "paused" : j.status;
  const lines = [`${j.mode === "live" ? "Live monitor" : "Scan"}: ${stateText}`];
  if (j.mode === "live") {
    lines.push(`polls ${j.polls} · every ${j.interval_seconds}s · last ${fmtTime(j.last_poll)} · history position ${j.next_offset}`
      + (j.buffered ? ` · ${j.buffered} waiting for a batch of ${j.min_batch}` : ""));
  }
  lines.push(`fetched ${j.fetched} · in scope ${j.in_scope} · unparsed ${j.unparsed} · new findings ${j.new_findings}`);
  const reasons = Object.entries(j.llm_discard_reasons || {}).map(([k, v]) => `${k}=${v}`).join(", ");
  lines.push(`model ${j.llm_done}/${j.llm_total} done · queue ${j.queue_depth}`
    + (j.llm_avg_seconds ? ` · ${j.llm_avg_seconds}s each` : "") + (j.eta_minutes ? ` · ~${j.eta_minutes} min left` : ""));
  if (j.skipped_endpoint_cap) lines.push(`skipped ${j.skipped_endpoint_cap} near-duplicate endpoints (see LLM_MAX_PER_ENDPOINT)`);
  if (j.llm_discarded) lines.push(`suggestions discarded: ${j.llm_discarded}${reasons ? " (" + reasons + ")" : ""}`);
  if (j.llm_errors) lines.push(`model errors: ${j.llm_errors}`);
  if (j.llm_last_error) lines.push(`last model error (${fmtTime(j.llm_last_error_at)}): ${j.llm_last_error}`);
  if (j.error) lines.push("ERROR: " + j.error);
  return lines.concat(j.warnings || []).join("\n");
}

function renderJob() {
  const j = state.job, active = isActive(j);
  const here = !!(j && state.engagement && j.engagement_id === state.engagement.id);
  const ro = readOnly();
  const show = (id, on) => ($(id).hidden = !on);
  $("scan-setup").disabled = active || ro;
  show("scan-go", !active && !ro);
  show("scan-pause", active && !j.paused);
  show("scan-resume", active && j.paused);
  show("scan-cancel", active);
  show("queue-clear", !active && !ro && state.queue > 0);
  $("queue-clear").textContent = `Clear model queue (${state.queue})`;
  $("scan-scope").textContent = state.engagement
    ? (state.engagement.scope.length ? `Scope for this engagement: ${state.engagement.scope.join(", ")}`
        : "This engagement has no scope yet: edit it from the engagement list before scanning.")
    : "";
  let text = "";
  if (j) text = (active && !here ? `Another engagement is scanning: "${j.engagement_name}". Pause or stop it to start one here.\n\n` : "") + describe(j);
  else if (state.queue) text = `${state.queue} items are waiting for model review from an earlier run.`;
  $("scan-status").textContent = text;

  const chip = $("live-chip"), aj = state.activeJob;
  chip.hidden = !aj;
  if (aj) {
    const paused = aj.status === "paused";
    chip.className = "chip live" + (paused ? " paused" : aj.mode === "live" ? "" : " busy");
    chip.replaceChildren(el("span", { class: "dot" }), document.createTextNode(
      `${paused ? "Paused" : aj.mode === "live" ? "Live" : "Scanning"} · ${aj.engagement_name}` + (aj.queue_depth ? ` · ${aj.queue_depth} queued` : "")));
  }
}

async function tick() {
  let delay = 8000;
  if (!state.authFailed) {
    try {
      const prev = jobKey(state.activeJob);
      state.activeJob = (await api("/status")).active_job;
      const mine = state.engagement ? await api("/scan") : [];
      state.job = state.activeJob || mine[mine.length - 1] || null;
      const here = state.job && state.engagement && state.job.engagement_id === state.engagement.id;
      if (here) {
        const changed = state.job.new_findings !== lastSeenNew || state.job.status !== lastSeenStatus;
        lastSeenNew = state.job.new_findings; lastSeenStatus = state.job.status;
        if (changed) await load(); else if ($("dlg-scan").open) loadStats();
      } else if (state.engagement && $("dlg-scan").open) loadStats();
      if (!state.engagement && jobKey(state.activeJob) !== prev) await refreshPicker();
      renderJob();
      delay = state.activeJob || $("dlg-scan").open ? 1500 : 8000;
    } catch { /* 401 handled in api(); retry later */ }
  }
  tickTimer = setTimeout(tick, delay);
}
const kick = () => { clearTimeout(tickTimer); tick(); };

// The scan panel is deliberately NOT modal: it floats at the corner so you can keep reviewing
// findings while a scan runs. Click Scan Burp… again (or Close) to hide or bring it back.
const toggleScan = () => {
  const d = $("dlg-scan");
  if (d.open) d.close(); else { d.show(); kick(); }
};
$("btn-scan").onclick = toggleScan;
$("live-chip").onclick = () => {
  if (state.engagement) { if (!$("dlg-scan").open) { $("dlg-scan").show(); kick(); } return; }
  const e = state.engagements.find((x) => x.id === state.activeJob?.engagement_id);
  if (e) openEngagement(e);
};
document.querySelectorAll("input[name=scan-mode]").forEach((r) => r.addEventListener("change", () => {
  $("row-live").hidden = mode() !== "live";
  $("row-count").hidden = mode() === "live";
}));

async function jobAction(path, opts = { method: "POST" }) {
  try { state.job = await api(path, opts); } catch (e) { $("scan-status").textContent = e.message; }
  renderJob(); kick();
}
$("scan-go").onclick = async () => {
  const live = mode() === "live";
  try {
    const body = { use_llm: $("scan-llm").checked, live };
    if (live) { body.interval_seconds = +$("scan-interval").value || 15; body.min_batch = +$("scan-batch").value || 1; }
    else body.count = +$("scan-count").value || 300;
    state.job = await api("/scan", { method: "POST", body: JSON.stringify(body) });
    lastSeenNew = -1;
    renderJob(); kick();
  } catch (e) { $("scan-status").textContent = e.message; }
};
$("scan-pause").onclick = () => jobAction(`/scan/${state.job.id}/pause`);
$("scan-resume").onclick = () => jobAction(`/scan/${state.job.id}/resume`);
$("scan-cancel").onclick = () => jobAction(`/scan/${state.job.id}/cancel`);
$("queue-clear").onclick = async () => {
  if (!confirm(`Discard the ${state.queue} items waiting for model review? Findings from the checks are kept.`)) return;
  try { await api("/queue", { method: "DELETE" }); } catch (e) { alert(e.message); }
  await load(); renderJob();
};

// ============================================================ WSTG coverage
const ST_TEXT = { findings: "findings", clear: "auto-checked, nothing found", tested: "tested manually", na: "not applicable", untested: "untested" };

function setCoverageView(on) {
  $("view-coverage").hidden = !on;
  $("view-review").hidden = on;
  $("btn-wstg").textContent = on ? "Back to findings" : "WSTG coverage";
  if (on) loadCoverage();
}
$("btn-wstg").onclick = () => setCoverageView($("view-coverage").hidden);

async function loadCoverage() {
  const body = $("cov-body");
  if (!state.cov) body.replaceChildren(el("p", { class: "hint", text: "Loading…" }));
  try { state.cov = await api("/wstg"); renderCoverage(); }
  catch (e) { body.replaceChildren(el("p", { class: "err", text: e.message })); }
}
$("cov-rebuild").onclick = async () => {
  try { await api("/wstg/rebuild", { method: "POST" }); } catch (e) { alert(e.message); }
  loadCoverage();
};

function renderCoverage() {
  const v = state.cov, s = v.summary;
  $("cov-summary").replaceChildren(...[
    [`${s.findings} with findings`, "warn"], [`${s.clear} auto-checked`, ""], [`${s.tested} tested manually`, ""],
    [`${s.na} not applicable`, ""], [`${s.untested} untested`, ""],
  ].map(([t, c]) => el("span", { class: "chip " + c, text: t })));
  $("cov-body").replaceChildren(...v.categories.map((cat) => {
    const withF = cat.tests.filter((t) => t.status === "findings").length;
    const done = cat.tests.filter((t) => t.status !== "untested").length;
    const d = el("details", { class: "cat" },
      el("summary", {}, el("span", { class: "grow", text: `${cat.code}: ${cat.name}` }),
        withF ? badge(`${withF} with findings`, "st-findings") : null,
        el("span", { class: "count", text: `${done}/${cat.tests.length} covered` })),
      ...cat.tests.map(testRow));
    d.open = state.covOpen.has(cat.code) || withF > 0;
    d.addEventListener("toggle", () => (d.open ? state.covOpen.add(cat.code) : state.covOpen.delete(cat.code)));
    return d;
  }));
}

function testRow(t) {
  const ro = readOnly();
  const sel = el("select", { "aria-label": "Manual status for " + t.id },
    el("option", { value: "", text: "Not set" }), el("option", { value: "tested", text: "Tested manually" }),
    el("option", { value: "na", text: "Not applicable" }));
  sel.value = t.manual.status;
  const note = el("textarea", { "aria-label": "Notes for " + t.id, placeholder: "What you tried, tools, results, why it doesn't apply…" });
  note.value = t.manual.note;
  sel.disabled = note.readOnly = ro;
  const saveBtn = el("button", { class: "ghost", text: "Save", onclick: async () => {
    try { await api("/wstg/" + t.id, { method: "PUT", body: JSON.stringify({ status: sel.value, note: note.value }) }); }
    catch (e) { alert(e.message); return; }
    state.covOpen.add(t.id.split("-")[0]); await loadCoverage();
  } });
  const label = t.status === "findings" ? `${t.open} finding${t.open > 1 ? "s" : ""}`
    : t.status === "clear" ? `${ST_TEXT.clear} · ${t.requests} request${t.requests > 1 ? "s" : ""}` : ST_TEXT[t.status];
  const hint = t.automated && t.status === "untested" ? "Automated checks exist for this test but no matching traffic has been captured yet."
    : !t.automated ? "No automated checks for this test: test it manually." : "";
  const badgeEl = badge(label, "st-" + t.status);
  if (hint) badgeEl.title = hint;
  const row = el("div", { class: "wtest" },
    el("div", { class: "line" }, el("span", { class: "tid", text: "WSTG-" + t.id }), el("span", { class: "tname", text: t.name }),
      badgeEl, t.manual.status && t.status === "findings" ? badge(ST_TEXT[t.manual.status], "st-" + t.manual.status) : null,
      t.open ? el("button", { class: "ghost", text: "Show findings", onclick: () => {
        state.wstgFilter = t.id; $("f-status").value = "";
        setCoverageView(false); load();
      } }) : null),
    el("details", {}, el("summary", { text: t.manual.note ? "Manual status and notes ●" : "Manual status and notes" }),
      el("div", { class: "row" }, el("label", { class: "inline" }, "Status ", sel)), note, ro ? null : el("div", { class: "row" }, saveBtn)));
  return row;
}

// ============================================================== report
// The format defaults to the engagement's type but can be switched when you generate it.
async function loadReport() {
  const fmt = $("report-format").value;
  $("row-cov").hidden = fmt !== "pentest";
  const cov = fmt === "pentest" && $("report-cov").checked ? "&coverage=true" : "";
  $("report-text").textContent = "Loading…";
  try { $("report-text").textContent = await api("/report?format=" + encodeURIComponent(fmt) + cov); }
  catch (e) { $("report-text").textContent = e.message; }
}
$("btn-report").onclick = async () => {
  $("report-format").value = state.engagement?.kind || "pentest";
  $("dlg-report").showModal();
  await loadReport();
};
$("report-format").addEventListener("change", loadReport);
$("report-cov").addEventListener("change", loadReport);
$("report-copy").onclick = () => navigator.clipboard?.writeText($("report-text").textContent);
$("report-dl").onclick = () => {
  const a = el("a", { href: URL.createObjectURL(new Blob([$("report-text").textContent], { type: "text/markdown" })),
    download: `${slug(state.engagement?.name || "report")}-${$("report-format").value}-report.md` });
  a.click(); URL.revokeObjectURL(a.href);
};

// ================================================================ logs
let logsTimer = null;
async function loadLogs() {
  const box = $("logs-text");
  try {
    const data = await api("/logs?limit=300&level=" + $("logs-level").value);
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    $("logs-file").textContent = data.file ? `Also saved to ${data.file}.` : "File logging is off (LOG_FILE).";
    box.replaceChildren(...(data.entries.length ? data.entries.map((e) =>
      el("span", { class: `ln lv-${e.level}` },
        el("span", { class: "ts", text: new Date(e.t).toLocaleTimeString() + " " }), `${e.level} ${e.message}`))
      : [el("span", { class: "ts", text: "Nothing logged at this level since the service started." })]));
    if (atBottom) box.scrollTop = box.scrollHeight;
  } catch (e) { box.replaceChildren(el("span", { class: "lv-ERROR", text: e.message })); }
}
function openLogs() {
  $("dlg-logs").showModal();
  loadLogs().then(() => ($("logs-text").scrollTop = $("logs-text").scrollHeight));
  clearInterval(logsTimer);
  logsTimer = setInterval(loadLogs, 3000);   // follows a running scan
}
$("dlg-logs").addEventListener("close", () => clearInterval(logsTimer));
$("btn-logs").onclick = openLogs;
$("scan-logs").onclick = openLogs;
$("logs-level").addEventListener("change", loadLogs);
$("logs-refresh").onclick = loadLogs;
$("logs-copy").onclick = () => navigator.clipboard?.writeText($("logs-text").innerText);

// =============================================================== token
$("btn-token").onclick = () => $("dlg-token").showModal();
$("token-save").onclick = () => {
  state.token = $("token-input").value;
  sessionStorage.setItem("token", state.token);
  $("token-input").value = "";
  state.authFailed = false;
  boot();
};

["f-status", "f-severity", "f-source"].forEach((id) => $(id).addEventListener("change", load));
$("f-search").addEventListener("input", render);
$("f-group").addEventListener("change", render);

// ================================================================ boot
// Order of events: token first (the API refuses without it), then choose an engagement.
async function boot() {
  try {
    await showEngagements();
    kick();
  } catch (e) {
    setView("picker");
    $("eng-msg").textContent = state.authFailed ? "Enter the API token to continue." : e.message;
    $("eng-msg").hidden = false;
  }
}
boot();
