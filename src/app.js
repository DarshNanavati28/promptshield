import { DEFAULT_POLICY, screenPrompt, validatePolicy } from "./policy-engine.js";
import { EVALUATION_CASES, evaluateCorpus } from "./evaluation.js";

const POLICY_KEY = "promptshield.policy.v1";
const main = document.querySelector("#app-main");
const state = {
  view: "overview",
  policy: readSavedPolicy(),
  audit: [],
  input: "",
  source: "user",
  lastResult: null,
  evaluation: null,
  toastTimer: null,
};

const NAV_LABELS = {
  overview: "Overview",
  inspector: "Prompt inspector",
  evaluation: "Evaluation",
  policy: "Policy editor",
  audit: "Decision log",
};

function readSavedPolicy() {
  try {
    const saved = localStorage.getItem(POLICY_KEY);
    return saved ? validatePolicy(JSON.parse(saved)) : validatePolicy(DEFAULT_POLICY);
  } catch {
    return validatePolicy(DEFAULT_POLICY);
  }
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function percent(value) {
  return value === null ? "—" : `${Math.round(value * 100)}%`;
}

function actionPill(action) {
  const labels = { allow: "Allowed", block: "Blocked", sanitize: "Sanitized", escalate: "Review" };
  return `<span class="pill pill-${escapeHtml(action)}">${labels[action] ?? escapeHtml(action)}</span>`;
}

function sourceLabel(source) {
  return ({ user: "User message", document: "Retrieved document", tool: "Tool output" })[source] ?? source;
}

function relativeTime(timestamp) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
  return new Date(timestamp).toLocaleString();
}

function toast(message) {
  const element = document.querySelector("#toast");
  element.textContent = message;
  element.classList.add("is-visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => element.classList.remove("is-visible"), 2200);
}

function updateNav() {
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("is-active", item.dataset.view === state.view));
  document.querySelector("#page-crumb").textContent = NAV_LABELS[state.view] ?? "Overview";
  const count = document.querySelector("#audit-count");
  count.textContent = state.audit.length;
  count.classList.toggle("is-visible", state.audit.length > 0);
}

function render() {
  updateNav();
  const evaluation = evaluateCorpus(state.policy);
  state.evaluation = evaluation;
  const renderers = {
    overview: renderOverview,
    inspector: renderInspector,
    evaluation: renderEvaluation,
    policy: renderPolicy,
    audit: renderAudit,
  };
  main.innerHTML = renderers[state.view]();
}

function renderOverview() {
  const evaluation = state.evaluation;
  const recent = state.audit.slice(0, 4);
  const activity = recent.length ? recent.map((event) => `
    <div class="activity-row">
      <span class="activity-icon">${event.action === "block" ? "⊘" : event.action === "escalate" ? "⌁" : event.action === "sanitize" ? "⌑" : "✓"}</span>
      <div class="activity-copy"><strong>${escapeHtml(event.reason)}</strong><small>${escapeHtml(sourceLabel(event.source))} · ${escapeHtml(relativeTime(event.timestamp))}</small></div>
      ${actionPill(event.action)}
    </div>`).join("") : `<div class="activity-empty">No decisions recorded yet. Screen a message to start a local session log.</div>`;
  return `
    <section class="hero-panel">
      <div class="hero-copy">
        <p class="eyebrow">A safer boundary for every model call</p>
        <h1>Good prompts get through.<br />Hidden instructions don’t.</h1>
        <p>Screen user messages, retrieved documents, and tool output before they reach the model. Every decision follows an editable policy and carries a reason.</p>
        <div class="hero-actions"><button class="btn btn-primary" data-view="inspector"><span class="btn-icon">⌕</span> Inspect content</button><button class="btn btn-secondary" data-view="evaluation">View evaluation set <span class="btn-icon">↗</span></button></div>
      </div>
      <div class="hero-visual" aria-hidden="true"><div class="shield-orbit"><span class="orbit-dot"></span><div class="shield-center"><svg viewBox="0 0 40 40" fill="none"><path d="M20 4.5 33.2 9v10.2c0 7.6-5 12.8-13.2 15.7C11.8 32 6.8 26.8 6.8 19.2V9L20 4.5Z" stroke="currentColor" stroke-width="1.6"/><path d="m14.3 19.8 3.8 3.8 7.7-8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></div><span class="hero-tag">SOURCE-AWARE SCREENING</span></div></div>
    </section>
    <section class="metric-grid" aria-label="Evaluation summary">
      <div class="metric-card"><span class="metric-glyph">◎</span><div class="metric-label">Labeled samples</div><div class="metric-value">${evaluation.total}<span class="metric-unit">cases</span></div><div class="metric-foot">${evaluation.malicious} malicious · ${evaluation.legitimate} legitimate</div></div>
      <div class="metric-card"><span class="metric-glyph">⌁</span><div class="metric-label">Attacks detected</div><div class="metric-value">${evaluation.truePositives}<span class="metric-unit">/ ${evaluation.malicious}</span></div><div class="metric-foot">${percent(evaluation.recall)} detection rate on this set</div></div>
      <div class="metric-card"><span class="metric-glyph">◌</span><div class="metric-label">False positives</div><div class="metric-value">${evaluation.falsePositives}<span class="metric-unit">/ ${evaluation.legitimate}</span></div><div class="metric-foot">${percent(evaluation.falsePositiveRate)} of legitimate samples flagged</div></div>
      <div class="metric-card"><span class="metric-glyph">!</span><div class="metric-label">Missed attacks</div><div class="metric-value">${evaluation.falseNegatives}<span class="metric-unit">cases</span></div><div class="metric-foot">Policy: ${escapeHtml(state.policy.name)}</div></div>
    </section>
    <section class="dashboard-grid">
      <article class="card activity-card"><div class="card-head"><div><h2>Recent decisions</h2><p>Session-only audit trail with a reason for each outcome.</p></div><button class="card-link" data-view="audit">Open decision log →</button></div><div class="activity-list">${activity}</div></article>
      <article class="card posture-card"><div class="card-head"><div><h2>Trust posture</h2><p>Content is assessed by where it came from.</p></div><span class="pill pill-allow">Active policy</span></div><div class="posture-list">
        <div class="posture-row"><span class="posture-check">✓</span><div><strong>User messages</strong><small>Screened for instruction changes, protected information, and data transfer.</small></div></div>
        <div class="posture-row"><span class="posture-check">✓</span><div><strong>Documents &amp; tool output</strong><small>Marked untrusted; instructions inside remain data and cannot edit policy.</small></div></div>
        <div class="posture-row"><span class="posture-check">✓</span><div><strong>Protected values</strong><small>Checked after case, spacing, punctuation, and simple encoding normalization.</small></div></div>
      </div></article>
    </section>
    <p class="section-label">The screening path</p>
    <section class="card trust-flow" aria-label="Prompt screening flow">
      <div class="flow-node"><span class="flow-node-icon">◉</span><div><strong>Incoming content</strong><small>User · document · tool</small></div></div><span class="flow-arrow">→</span>
      <div class="flow-node"><span class="flow-node-icon">⌕</span><div><strong>Policy screening</strong><small>Source-aware checks</small></div></div><span class="flow-arrow">→</span>
      <div class="flow-node"><span class="flow-node-icon">✓</span><div><strong>Model boundary</strong><small>Allow · sanitize · hold</small></div></div>
    </section>`;
}

function renderInspector() {
  const examples = [
    ["D-01", "Direct override"], ["I-01", "Document injection"], ["I-03", "Encoded value"], ["I-09", "Sanitize + preserve"], ["B-01", "Benign quote"],
  ];
  const result = state.lastResult ? renderDecision(state.lastResult) : `<div class="result-placeholder"><div><div class="result-placeholder-mark">⌕</div><strong>Ready to inspect</strong><p>Choose a source, paste content, then screen it against the active policy.</p></div></div>`;
  return `
    <section class="view-head"><div><p class="eyebrow">Interactive screening</p><h1>Prompt inspector</h1><p>Check a direct prompt or simulated retrieved content. The gate returns one policy outcome and a recorded reason before any model call.</p></div></section>
    <section class="inspector-layout">
      <article class="card form-card">
        <div class="form-section"><div class="form-row"><div><label class="field-label" for="source-select">Content source</label><p class="field-help">Source changes how suspicious instructions are handled.</p></div><select id="source-select" class="select-control"><option value="user" ${state.source === "user" ? "selected" : ""}>User message</option><option value="document" ${state.source === "document" ? "selected" : ""}>Retrieved document</option><option value="tool" ${state.source === "tool" ? "selected" : ""}>Tool output</option></select></div></div>
        <div class="form-section"><label class="field-label" for="prompt-input">Content to screen</label><textarea class="textarea" id="prompt-input" placeholder="Paste user text, a document excerpt, or simulated tool output…">${escapeHtml(state.input)}</textarea><div class="quick-examples">${examples.map(([id, label]) => `<button class="example-chip" data-example="${id}">${label}</button>`).join("")}</div><div class="form-actions"><small>Nothing is sent to a language model.</small><button class="btn btn-primary" data-action="inspect"><span class="btn-icon">⌕</span> Screen content</button></div></div>
      </article>
      <article class="card result-panel"><div class="card-head"><div><h2>Decision</h2><p>Outcome, evidence, and the content allowed downstream.</p></div><span class="pill pill-allow">Before model</span></div>${result}</article>
    </section>
    <div class="policy-callout"><span>ⓘ</span><span><b>Untrusted text is data.</b> Document and tool instructions are inspected as content. They are never merged into, or allowed to change, the active policy.</span></div>`;
}

function renderDecision(result) {
  const action = result.action;
  const headline = ({ allow: "Content allowed", sanitize: "Offending text removed", block: "Content blocked", escalate: "Held for review" })[action];
  const mark = ({ allow: "✓", sanitize: "⌑", block: "×", escalate: "!" })[action];
  const output = result.allowed
    ? `<div class="output-box"><div class="output-box-head"><span>${action === "sanitize" ? "Sanitized content for model" : "Content for model"}</span>${action === "sanitize" ? `<span class="pill pill-sanitize">Sanitized</span>` : `<button class="btn btn-quiet btn-small" data-action="copy-output">Copy</button>`}</div><p class="output-text">${escapeHtml(result.text || "[empty after sanitization]")}</p>${action === "sanitize" ? `<button class="btn btn-quiet btn-small" data-action="copy-output">Copy safe text</button>` : ""}</div>`
    : `<div class="output-box"><div class="output-box-head"><span>Model handoff</span></div><div class="no-output">This content was not passed downstream. ${action === "escalate" ? "A reviewer must resolve it first." : "The request was stopped by policy."}</div></div>`;
  const findings = result.findings.length ? `<div class="finding-list">${result.findings.map((finding) => `
    <div class="finding-row"><div class="finding-row-top"><strong>${escapeHtml(finding.label)}</strong>${actionPill(finding.action)}</div><p>${escapeHtml(finding.category === "protected_value" ? "Configured protected value matched (value redacted)." : finding.evidence || finding.reason)}</p></div>`).join("")}</div>` : `<div class="finding-row finding-empty"><div class="finding-row-top"><strong>No policy findings</strong>${actionPill("allow")}</div><p>${escapeHtml(result.reason)}</p></div>`;
  return `<div class="result-top"><span>Screening result</span><span class="table-sub">${escapeHtml(sourceLabel(result.source))}</span></div><div class="result-body"><div class="decision-banner ${escapeHtml(action)}"><span class="decision-mark">${mark}</span><div class="decision-copy"><strong>${headline}</strong><p>${escapeHtml(result.reason)}</p></div></div>${findings}${output}</div>`;
}

function renderEvaluation() {
  const report = state.evaluation;
  const rows = report.cases.map((item) => {
    const rowClass = item.missed ? "row-missed" : item.falsePositive ? "row-fp" : "";
    const status = item.missed ? `<span class="pill pill-block">Missed</span>` : item.falsePositive ? `<span class="pill pill-escalate">False positive</span>` : `<span class="pill pill-allow">Correct</span>`;
    const reason = item.findings.length ? item.findings.map(({ label }) => label).join(" · ") : "No finding";
    return `<tr class="${rowClass}"><td><span class="table-main">${escapeHtml(item.id)} · ${escapeHtml(item.label)}</span><span class="table-sub">${escapeHtml(sourceLabel(item.source))}</span></td><td class="case-kind">${escapeHtml(item.kind)}</td><td>${item.malicious ? `<span class="pill pill-block">Malicious</span>` : `<span class="pill pill-allow">Legitimate</span>`}</td><td>${actionPill(item.outcome)}</td><td>${status}<span class="table-sub">${escapeHtml(reason)}</span></td></tr>`;
  }).join("");
  return `
    <section class="view-head"><div><p class="eyebrow">Labeled benchmark · ${report.total} examples</p><h1>Evaluation</h1><p>Run the current policy against direct attacks, indirect content, obfuscated protected values, and ordinary requests. Misses and false positives stay visible.</p></div><button class="btn btn-secondary" data-action="rerun-eval"><span class="btn-icon">↻</span> Re-run evaluation</button></section>
    <section class="evaluation-hero"><div class="eval-meta"><strong>${escapeHtml(report.policy.name)} · v${escapeHtml(report.policy.version)}</strong><span>Local deterministic benchmark · results computed from the examples below</span></div><span class="pill pill-allow">${report.total} cases · no model calls</span></section>
    <section class="eval-grid">
      <div class="eval-stat"><small>Attacks detected</small><strong>${report.truePositives} / ${report.malicious}</strong><span>${percent(report.recall)} recall on this fixture set</span></div>
      <div class="eval-stat"><small>False positives</small><strong>${report.falsePositives}</strong><span>${percent(report.falsePositiveRate)} of legitimate samples</span></div>
      <div class="eval-stat"><small>Missed attacks</small><strong>${report.falseNegatives}</strong><span>Attacks that passed as allow</span></div>
      <div class="eval-stat"><small>Precision</small><strong>${percent(report.precision)}</strong><span>Detected cases that were malicious</span></div>
    </section>
    <div class="eval-disclaimer"><span>!</span><span><b>Read this as a fixture score, not a security guarantee.</b> The corpus is small, hand-labeled, and intentionally inspectable. Add domain-specific cases and review every miss before using a policy in production.</span></div>
    <article class="card"><div class="card-head"><div><h2>Case-by-case results</h2><p>Direct and indirect samples, with each classifier outcome and reason.</p></div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Example</th><th>Type</th><th>Label</th><th>Outcome</th><th>Assessment</th></tr></thead><tbody>${rows}</tbody></table></div></article>`;
}

function renderPolicy() {
  const json = JSON.stringify(state.policy, null, 2);
  const labels = {
    instruction_override: ["Instruction override", "Attempts to replace trusted instructions or expose hidden prompts."],
    protected_disclosure: ["Protected disclosure", "Requests for credentials, private context, or internal prompts."],
    external_exfiltration: ["External data transfer", "Sensitive content paired with an outside destination."],
    protected_value: ["Protected value match", "Configured values found after normalization or simple decoding."],
    suspicious_context: ["Suspicious untrusted instruction", "Assistant-directed requests found in retrieved content."],
  };
  const rows = Object.entries(state.policy.actions).map(([category, action]) => `<div class="policy-map-row"><div><strong>${labels[category][0]}</strong><small>${labels[category][1]}</small></div>${actionPill(action)}</div>`).join("");
  const sourceRows = ["user", "document", "tool"].map((source) => {
    const description = source === "user" ? "Direct messages use the category actions." : source === "document" ? "Retrieved text is untrusted; suspicious assistant-directed clauses are removed." : "Tool responses stay untrusted even when they sound authoritative; suspicious clauses are removed.";
    const overrideCount = Object.keys(state.policy.sourceOverrides[source] ?? {}).length;
    return `<div class="policy-source"><div class="policy-source-head"><strong>${sourceLabel(source)}</strong><span class="table-sub">${overrideCount ? `${overrideCount} override${overrideCount === 1 ? "" : "s"}` : "Base policy"}</span></div><p>${description}</p></div>`;
  }).join("");
  return `
    <section class="view-head"><div><p class="eyebrow">Explicit and editable</p><h1>Policy editor</h1><p>Change the decisions applied to each category. Policy changes are an explicit operator action; screened content cannot write to this configuration.</p></div></section>
    <section class="policy-layout">
      <article class="card"><div class="card-head"><div><h2>Active policy JSON</h2><p>Choose <span class="inline-code">allow</span>, <span class="inline-code">block</span>, <span class="inline-code">sanitize</span>, or <span class="inline-code">escalate</span> per category and source.</p></div><span class="pill pill-allow">v${escapeHtml(state.policy.version)}</span></div><div class="card-body"><textarea id="policy-json" class="policy-editor" spellcheck="false" aria-label="Editable policy JSON">${escapeHtml(json)}</textarea><div class="policy-actions"><button class="btn btn-primary" data-action="save-policy">Save policy</button><button class="btn btn-secondary" data-action="reset-policy">Restore defaults</button></div><p id="policy-status" class="policy-status" role="status">Changes apply to the inspector and evaluation after saving.</p><div class="policy-callout"><span>ⓘ</span><span>The demo policy and protected-value examples live in this browser’s local storage. Use sample markers here; do not paste live passwords, keys, or tokens into a browser policy editor.</span></div></div></article>
      <div>
        <article class="card"><div class="card-head"><div><h2>Category actions</h2><p>Fallback action when a finding matches.</p></div></div><div class="card-body"><div class="policy-map">${rows}</div></div></article>
        <article class="card stack-gap"><div class="card-head"><div><h2>Source treatment</h2><p>Provenance remains attached through screening.</p></div></div><div class="card-body"><div class="policy-source-list">${sourceRows}</div></div></article>
      </div>
    </section>`;
}

function renderAudit() {
  const rows = state.audit.map((event) => `<tr><td><span class="table-main">${escapeHtml(sourceLabel(event.source))}</span><span class="table-sub">${escapeHtml(new Date(event.timestamp).toLocaleString())}</span></td><td>${actionPill(event.action)}</td><td><span class="table-main">${escapeHtml(event.reason)}</span><span class="table-sub">${escapeHtml(event.categories.length ? event.categories.join(" · ") : "No findings")}</span></td><td><span class="output-text">${escapeHtml(event.excerpt || "—")}</span></td></tr>`).join("");
  const content = state.audit.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Source &amp; time</th><th>Outcome</th><th>Recorded reason</th><th>Redacted preview</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="empty-state"><div><div class="empty-state-mark">≡</div><strong>No decisions yet</strong><p>Run a screen in the Prompt inspector. Each decision and its policy reason will appear here for this browser session.</p><button class="btn btn-primary empty-action" data-view="inspector">Open inspector</button></div></div>`;
  return `
    <section class="view-head"><div><p class="eyebrow">Reasoned outcomes</p><h1>Decision log</h1><p>Review allow, block, sanitize, and escalation decisions made in this browser session.</p></div></section>
    <div class="audit-toolbar"><p>${state.audit.length} decision${state.audit.length === 1 ? "" : "s"} recorded · original content is not retained here · protected values are redacted</p>${state.audit.length ? `<button class="btn btn-danger btn-small" data-action="clear-audit">Clear session log</button>` : ""}</div>
    <article class="card">${content}</article>`;
}

function setView(view) {
  if (!NAV_LABELS[view]) return;
  state.view = view;
  render();
  main.focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function screenCurrentInput() {
  const input = document.querySelector("#prompt-input");
  const source = document.querySelector("#source-select");
  state.input = input?.value ?? state.input;
  state.source = source?.value ?? state.source;
  const result = screenPrompt({ text: state.input, source: state.source }, state.policy);
  state.lastResult = result;
  state.audit.unshift(result.auditEvent);
  state.audit = state.audit.slice(0, 75);
  render();
  toast(`Decision recorded: ${result.action}`);
}

function savePolicy() {
  const status = document.querySelector("#policy-status");
  try {
    const candidate = JSON.parse(document.querySelector("#policy-json").value);
    const policy = validatePolicy(candidate);
    localStorage.setItem(POLICY_KEY, JSON.stringify(policy));
    state.policy = policy;
    state.lastResult = null;
    render();
    const newStatus = document.querySelector("#policy-status");
    newStatus.textContent = "Policy saved locally. Inspector and evaluation now use this version.";
    toast("Policy saved to this browser");
  } catch (error) {
    status.textContent = error instanceof SyntaxError ? "Could not parse JSON. Check commas, quotes, and braces." : error.message;
    status.classList.add("error");
  }
}

async function copyOutput() {
  if (!state.lastResult?.allowed) return;
  try {
    await navigator.clipboard.writeText(state.lastResult.text);
    toast("Safe content copied");
  } catch {
    toast("Clipboard permission is unavailable in this browser");
  }
}

function handleClick(event) {
  const target = event.target.closest("[data-view], [data-action], [data-example]");
  if (!target) return;
  if (target.dataset.view) {
    event.preventDefault();
    setView(target.dataset.view);
    return;
  }
  if (target.dataset.example) {
    const fixture = EVALUATION_CASES.find(({ id }) => id === target.dataset.example);
    if (fixture) {
      state.input = fixture.text;
      state.source = fixture.source;
      state.lastResult = null;
      render();
    }
    return;
  }
  switch (target.dataset.action) {
    case "inspect": screenCurrentInput(); break;
    case "rerun-eval": state.evaluation = evaluateCorpus(state.policy); render(); toast("Evaluation refreshed against the active policy"); break;
    case "save-policy": savePolicy(); break;
    case "reset-policy":
      state.policy = validatePolicy(DEFAULT_POLICY);
      localStorage.removeItem(POLICY_KEY);
      state.lastResult = null;
      render();
      toast("Default policy restored");
      break;
    case "clear-audit": state.audit = []; render(); toast("Session decision log cleared"); break;
    case "copy-output": void copyOutput(); break;
    default: break;
  }
}

document.addEventListener("click", handleClick);
document.addEventListener("change", (event) => {
  if (event.target.id === "source-select") state.source = event.target.value;
});
document.addEventListener("input", (event) => {
  if (event.target.id === "prompt-input") state.input = event.target.value;
});
document.addEventListener("keydown", (event) => {
  if (event.target.id === "policy-json" && event.key === "Tab") {
    event.preventDefault();
    const start = event.target.selectionStart;
    const end = event.target.selectionEnd;
    event.target.setRangeText("  ", start, end, "end");
  }
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && state.view === "inspector") screenCurrentInput();
});

render();
