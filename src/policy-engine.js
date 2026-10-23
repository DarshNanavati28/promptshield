const ACTIONS = new Set(["allow", "block", "sanitize", "escalate"]);
const SOURCES = new Set(["user", "document", "tool"]);
const CATEGORIES = [
  "instruction_override",
  "protected_disclosure",
  "external_exfiltration",
  "protected_value",
  "suspicious_context",
];
const ACTION_RANK = { allow: 0, sanitize: 1, escalate: 2, block: 3 };

export const DEFAULT_POLICY = Object.freeze({
  name: "Balanced guardrails",
  version: "1.0",
  actions: {
    instruction_override: "block",
    protected_disclosure: "block",
    external_exfiltration: "block",
    protected_value: "block",
    suspicious_context: "escalate",
  },
  sourceOverrides: {
    user: {},
    document: { suspicious_context: "sanitize" },
    tool: { suspicious_context: "sanitize" },
  },
  protectedValues: ["PSHLD-DEMO-42", "northstar-demo-token"],
});

const CATEGORY_LABELS = {
  instruction_override: "Instruction override",
  protected_disclosure: "Protected information request",
  external_exfiltration: "External data transfer",
  protected_value: "Protected value match",
  suspicious_context: "Suspicious untrusted instruction",
};

const PATTERNS = {
  instruction_override: [
    /\b(?:ignore|disregard|forget|override|bypass|supersede|replace)\b[^.!?\n]{0,100}\b(?:instructions?|rules?|policy|system prompt|developer prompt|safety(?:\s+policy|\s+rules?)?)\b/gi,
    /\bdo not follow\b[^.!?\n]{0,60}\b(?:system|developer|previous|safety|policy|instructions?)\b[^.!?\n]*/gi,
    /\b(?:new instruction|system override)\b[^.!?\n]{0,100}\b(?:ignore|disregard|reveal|override|bypass|dump|leak|exfiltrate|send|show)\b[^.!?\n]{0,60}\b(?:system|developer|safety|secret|prompt|instructions?|credentials?|token|key)\b/gi,
    /\bfrom now on\b[^.!?\n]{0,80}\b(?:ignore|disregard|reveal|override|bypass|dump|leak|exfiltrate|send)\b[^.!?\n]{0,60}\b(?:system|developer|safety|secret|prompt|instructions?|credentials?|token|key)\b/gi,
    /\b(?:reveal|print|show|repeat|output|leak|expose|dump)\b[^.!?\n]{0,70}\b(?:hidden|system|developer|internal|confidential)\b[^.!?\n]{0,35}\b(?:prompt|instructions?|policy|message|content)\b/gi,
  ],
  protected_disclosure: [
    /\b(?:reveal|print|show|repeat|output|leak|expose|dump|disclose|return)\b[^.!?\n]{0,80}\b(?:api\s*keys?|credentials?|passwords?|access\s*tokens?|secrets?|private\s*keys?|hidden\s+(?:data|context|instructions?)|system\s+prompt|developer\s+prompt|internal\s+(?:prompt|instructions?|data)|environment\s+variables?)\b/gi,
    /\b(?:what is|give me|extract|retrieve|tell me (?:the|your|our))\b[^.!?\n]{0,65}\b(?:api\s*keys?|credentials?|passwords?|access\s*tokens?|secrets?|private\s*keys?|hidden\s+(?:data|context|instructions?|prompt)|system\s+prompt|developer\s+prompt)\b/gi,
  ],
  external_exfiltration: [
    /\b(?:send|email|upload|post|forward|transmit|exfiltrate|copy|paste|submit|sync)\b[^.!?\n]{0,150}\b(?:to|at|into)\s*(?:https?:\/\/|www\.|[\w.+-]+@[\w.-]+\.[a-z]{2,}|[\w.-]+\.(?:com|net|org|io|dev|app|ru)\b|external\b|outside\b|attacker\b|webhook\b|third[ -]party\b)[^.!?\n]*/gi,
  ],
  suspicious_context: [
    /\b(?:assistant|chatbot|language model|ai)\b[^.!?\n]{0,55}\b(?:must|should|please|now|always)\b[^.!?\n]{0,65}\b(?:ignore|reveal|send|call|invoke|upload|disclose|override|bypass)\b[^.!?\n]*/gi,
    /\b(?:secretly|without telling the user|silently)\b[^.!?\n]{0,90}\b(?:send|upload|reveal|copy|forward|disclose|exfiltrate)\b[^.!?\n]*/gi,
  ],
};

const SENSITIVE_TERMS = /\b(?:secret|credential|password|api\s*key|access\s*token|private\s*key|(?:system|developer|hidden|internal)\s+prompts?|hidden\s+instructions?|environment\s+variables?|customer\s+records?|(?:private|personal|protected)\s+data|workspace\s+context|config(?:uration)?\s+secrets?)\b/i;
const OUTBOUND_VERB = /\b(?:send|email|upload|post|forward|transmit|exfiltrate|copy|paste|submit|sync)\b/i;
const EXTERNAL_DESTINATION = /(?:https?:\/\/|www\.|[\w.+-]+@[\w.-]+\.[a-z]{2,}|[\w.-]+\.(?:com|net|org|io|dev|app|ru)\b|\b(?:external|outside|attacker|webhook|third[ -]party)\b)/i;

export function validatePolicy(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new TypeError("Policy must be a JSON object.");
  }
  const policy = structuredClone(DEFAULT_POLICY);
  if (candidate.name !== undefined) {
    if (typeof candidate.name !== "string" || candidate.name.trim().length < 1 || candidate.name.length > 80) {
      throw new TypeError("Policy name must be 1–80 characters.");
    }
    policy.name = candidate.name.trim();
  }
  if (candidate.version !== undefined) {
    if (typeof candidate.version !== "string" || candidate.version.length > 30) {
      throw new TypeError("Policy version must be a string of up to 30 characters.");
    }
    policy.version = candidate.version;
  }
  for (const category of CATEGORIES) {
    const action = candidate.actions?.[category] ?? policy.actions[category];
    if (!ACTIONS.has(action)) throw new TypeError(`Invalid action for ${category}.`);
    policy.actions[category] = action;
  }
  for (const source of SOURCES) {
    const overrides = candidate.sourceOverrides?.[source] ?? policy.sourceOverrides[source];
    if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) {
      throw new TypeError(`Overrides for ${source} must be an object.`);
    }
    policy.sourceOverrides[source] = {};
    for (const [category, action] of Object.entries(overrides)) {
      if (!CATEGORIES.includes(category)) throw new TypeError(`Unknown category: ${category}.`);
      if (!ACTIONS.has(action)) throw new TypeError(`Invalid action for ${source}.${category}.`);
      policy.sourceOverrides[source][category] = action;
    }
  }
  const protectedValues = candidate.protectedValues ?? policy.protectedValues;
  if (!Array.isArray(protectedValues) || protectedValues.length > 100 || protectedValues.some((value) => typeof value !== "string" || value.length > 512)) {
    throw new TypeError("protectedValues must be an array of up to 100 strings (512 characters each). ");
  }
  policy.protectedValues = [...new Set(protectedValues.map((value) => value.trim()).filter(Boolean))];
  return policy;
}

function canonicalWithMap(value) {
  let canonical = "";
  const starts = [];
  const ends = [];
  for (let index = 0; index < value.length; index += 1) {
    const normalized = value[index].normalize("NFKC").toLowerCase();
    const expanded = normalized.replace(/[013457]/g, (digit) => ({ 0: "o", 1: "i", 3: "e", 4: "a", 5: "s", 7: "t" })[digit]);
    for (const character of expanded) {
      if (/^[\p{L}\p{N}]$/u.test(character)) {
        canonical += character;
        starts.push(index);
        ends.push(index + 1);
      }
    }
  }
  return { canonical, starts, ends };
}

function decodeHtmlEntities(text) {
  return text.replace(/&#(x[\da-f]+|\d+);?/gi, (_match, code) => {
    const point = code[0].toLowerCase() === "x" ? parseInt(code.slice(1), 16) : parseInt(code, 10);
    return Number.isFinite(point) && point <= 0x10ffff ? String.fromCodePoint(point) : "";
  }).replace(/&(colon|sol|period|commat);/gi, (_match, name) => ({ colon: ":", sol: "/", period: ".", commat: "@" })[name.toLowerCase()]);
}

function decodingCandidates(text) {
  const candidates = [{ text, start: 0, end: text.length, precise: true, encoding: "plain text" }];
  if (/%[\da-f]{2}/i.test(text)) {
    try {
      candidates.push({ text: decodeURIComponent(text), start: 0, end: text.length, precise: false, encoding: "URL encoding" });
    } catch { /* malformed percent sequences stay as ordinary text */ }
  }
  const html = decodeHtmlEntities(text);
  if (html !== text) candidates.push({ text: html, start: 0, end: text.length, precise: false, encoding: "HTML entities" });
  const tokens = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/])/g;
  for (const match of text.matchAll(tokens)) {
    try {
      const decoded = atob(match[0]);
      const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
      const printable = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      if (/[\p{L}\p{N}]/u.test(printable)) candidates.push({ text: printable, start: match.index, end: match.index + match[0].length, precise: true, encoding: "Base64" });
    } catch { /* not valid base64 */ }
  }
  const hexTokens = /(?<![\da-f])[\da-f]{12,}(?![\da-f])/gi;
  for (const match of text.matchAll(hexTokens)) {
    if (match[0].length % 2 !== 0) continue;
    const decoded = match[0].match(/../g).map((byte) => String.fromCharCode(parseInt(byte, 16))).join("");
    if (/[\p{L}\p{N}]/u.test(decoded)) candidates.push({ text: decoded, start: match.index, end: match.index + match[0].length, precise: true, encoding: "hexadecimal" });
  }
  return candidates;
}

function findProtectedMatches(text, protectedValues) {
  const matches = [];
  for (const candidate of decodingCandidates(text)) {
    const content = canonicalWithMap(candidate.text);
    for (const secret of protectedValues) {
      const needle = canonicalWithMap(secret).canonical;
      if (needle.length < 4) continue;
      let position = content.canonical.indexOf(needle);
      while (position !== -1) {
        const start = candidate.precise ? candidate.start + content.starts[position] : candidate.start;
        const end = candidate.precise ? candidate.start + content.ends[position + needle.length - 1] : candidate.end;
        matches.push({ start, end, precise: candidate.precise, valueLabel: "configured protected value", encoding: candidate.encoding });
        position = content.canonical.indexOf(needle, position + needle.length);
      }
    }
  }
  return matches.filter((match, index, list) => list.findIndex((other) => other.start === match.start && other.end === match.end) === index);
}

function analysisContext(text, start) {
  const prefix = text.slice(Math.max(0, start - 150), start);
  const explicitFrame = /(?:example|quoted|phrase|prompt|injection|attack|sample|text|string|says?)\b[^.!?\n]{0,100}(?:["'“‘:]|\bis\b)?\s*$/i.test(prefix);
  const analyticalVerb = /\b(?:explain|analy[sz]e|describe|classify|detect|identify|study|review|document|teach|learn|defend|protect|handle|understand|recognize|evaluate|benchmark|simulate|discuss)\b/i.test(prefix);
  return explicitFrame && analyticalVerb;
}

function collectPatternFindings(text, source) {
  const findings = [];
  for (const [category, patterns] of Object.entries(PATTERNS)) {
    for (const pattern of patterns) {
      for (const match of text.matchAll(pattern)) {
        if (category === "external_exfiltration" && !SENSITIVE_TERMS.test(match[0])) continue;
        const start = match.index;
        const end = start + match[0].length;
        if (source === "user" && analysisContext(text, start)) continue;
        findings.push({
          category,
          label: CATEGORY_LABELS[category],
          start,
          end,
          precise: true,
          evidence: match[0].trim(),
          reason: categoryReason(category, source),
        });
      }
    }
  }
  for (const match of text.matchAll(/[^.!?\n]{0,180}[.!?]?/g)) {
    const clause = match[0];
    if (!clause.trim() || !OUTBOUND_VERB.test(clause) || !EXTERNAL_DESTINATION.test(clause) || !SENSITIVE_TERMS.test(clause)) continue;
    const start = match.index;
    if (source === "user" && analysisContext(text, start)) continue;
    findings.push({
      category: "external_exfiltration",
      label: CATEGORY_LABELS.external_exfiltration,
      start,
      end: start + clause.length,
      precise: true,
      evidence: clause.trim(),
      reason: categoryReason("external_exfiltration", source),
    });
  }
  return findings;
}

function categoryReason(category, source) {
  const origin = source === "user" ? "User-entered text" : source === "tool" ? "Tool output" : "Retrieved document text";
  const descriptions = {
    instruction_override: "attempts to replace or override assistant instructions",
    protected_disclosure: "requests protected prompts, credentials, or private context",
    external_exfiltration: "pairs sensitive information with an external destination",
    suspicious_context: "contains an instruction aimed at the assistant",
  };
  return `${origin} ${descriptions[category]}.`;
}

function actionFor(policy, source, category) {
  return policy.sourceOverrides?.[source]?.[category] ?? policy.actions[category] ?? "allow";
}

function redactExcerpt(text, findings, protectedValues) {
  const spans = findings.map(({ start, end }) => ({ start, end }));
  for (const match of findProtectedMatches(text, protectedValues)) spans.push(match);
  const merged = mergeSpans(spans);
  let redacted = text;
  for (const span of merged.reverse()) redacted = `${redacted.slice(0, span.start)}[redacted]${redacted.slice(span.end)}`;
  return redacted.replace(/\s+/g, " ").trim().slice(0, 140);
}

function mergeSpans(spans) {
  const sorted = spans.filter((span) => Number.isInteger(span.start) && Number.isInteger(span.end) && span.end > span.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const merged = [];
  for (const span of sorted) {
    const last = merged.at(-1);
    if (last && span.start <= last.end) last.end = Math.max(last.end, span.end);
    else merged.push({ start: span.start, end: span.end });
  }
  return merged;
}

function stripSpans(text, spans) {
  let output = text;
  const removable = mergeSpans(spans).map((span) => ({
    ...span,
    end: /[.!?]/.test(text[span.end] ?? "") ? span.end + 1 : span.end,
  }));
  for (const span of removable.reverse()) output = `${output.slice(0, span.start)}${output.slice(span.end)}`;
  return output.replace(/[ \t]{2,}/g, " ").replace(/\s+([,.!?;:])/g, "$1").replace(/[ \t]+\n/g, "\n").trim();
}

export function screenPrompt(input, candidatePolicy = DEFAULT_POLICY) {
  const policy = validatePolicy(candidatePolicy);
  const source = SOURCES.has(input?.source) ? input.source : "user";
  const text = typeof input?.text === "string" ? input.text : "";
  const findings = collectPatternFindings(text, source);
  for (const match of findProtectedMatches(text, policy.protectedValues)) {
    findings.push({
      category: "protected_value",
      label: CATEGORY_LABELS.protected_value,
      start: match.start,
      end: match.end,
      precise: match.precise,
      evidence: match.precise ? text.slice(match.start, match.end) : "encoded protected value",
      reason: `A configured protected value matched after ${match.encoding} normalization.`,
    });
  }
  const unique = findings.filter((finding, index, list) => list.findIndex((other) => other.category === finding.category && other.start === finding.start && other.end === finding.end) === index);
  const assessed = unique.map((finding) => ({ ...finding, action: actionFor(policy, source, finding.category) }));
  const requestedAction = assessed.reduce((selected, finding) => ACTION_RANK[finding.action] > ACTION_RANK[selected] ? finding.action : selected, "allow");
  const needsImpreciseSanitization = requestedAction === "sanitize" && assessed.some((finding) => finding.action === "sanitize" && finding.precise === false);
  const action = needsImpreciseSanitization ? "escalate" : requestedAction;
  const removedFindings = assessed.filter((finding) => finding.action === "sanitize");
  const sanitizedText = action === "sanitize" ? stripSpans(text, removedFindings) : text;
  const primaryReason = needsImpreciseSanitization
    ? "A protected value was found in an encoding whose exact source span is ambiguous; review is required before removing text."
    : assessed.length
      ? [...new Set(assessed.filter((finding) => finding.action === action).map((finding) => finding.reason))].join(" ")
      : "No policy violations found. Content was screened according to its declared source.";
  const timestamp = new Date().toISOString();
  const auditEvent = {
    id: `ps-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp,
    source,
    action,
    reason: primaryReason,
    categories: [...new Set(assessed.map(({ category }) => category))],
    excerpt: redactExcerpt(text, assessed, policy.protectedValues),
  };
  return {
    action,
    allowed: action === "allow" || action === "sanitize",
    source,
    text: sanitizedText,
    originalText: text,
    reason: primaryReason,
    findings: assessed.map(({ category, label, start, end, evidence, action: findingAction, reason, precise }) => ({
      category, label, start, end, evidence, action: findingAction, reason, precise,
    })),
    auditEvent,
  };
}

export function screenMessages(messages, candidatePolicy = DEFAULT_POLICY) {
  const safeMessages = [];
  const decisions = [];
  for (const message of messages) {
    if (!message || typeof message !== "object") {
      safeMessages.push(message);
      continue;
    }
    const role = String(message.role ?? "user").toLowerCase();
    const declaredSource = SOURCES.has(message.source) ? message.source : null;
    const source = role === "tool" ? "tool" : role === "document" ? "document" : declaredSource ?? (role === "user" ? "user" : null);
    if (!source || typeof message.content !== "string") {
      safeMessages.push(message);
      continue;
    }
    const decision = screenPrompt({ text: message.content, source }, candidatePolicy);
    decisions.push(decision);
    if (!decision.allowed) {
      return { allowed: false, action: decision.action, reason: decision.reason, messages: null, decisions };
    }
    safeMessages.push(decision.action === "sanitize" ? { ...message, content: decision.text } : message);
  }
  return { allowed: true, action: decisions.some(({ action }) => action === "sanitize") ? "sanitize" : "allow", reason: "All untrusted messages passed policy screening.", messages: safeMessages, decisions };
}

export function createPromptShield(candidatePolicy = DEFAULT_POLICY) {
  const policy = validatePolicy(candidatePolicy);
  return {
    policy,
    screen: (input) => screenPrompt(input, policy),
    screenMessages: (messages) => screenMessages(messages, policy),
    async wrapModelCall(modelCall, messages) {
      const gate = screenMessages(messages, policy);
      if (!gate.allowed) return { blocked: true, action: gate.action, reason: gate.reason, decisions: gate.decisions };
      const response = await modelCall(gate.messages);
      return { blocked: false, action: gate.action, response, decisions: gate.decisions };
    },
  };
}
