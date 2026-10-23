# PromptShield

PromptShield is a small, source-aware middleware demo for stopping prompt injection and data-exfiltration attempts before content reaches a language model. It includes an interactive review console, an editable policy, a labeled evaluation corpus, and a dependency-free JavaScript gate.

## Run it locally

Requires Node.js 20 or newer. No packages need to be installed.

```bash
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). The demo screens content in your browser and makes no language-model or network calls. Policy edits are stored in this browser's local storage. The decision log is kept only for the current page session.

## Use the middleware

```js
import { createPromptShield } from "./src/policy-engine.js";

const shield = createPromptShield(policy);
const result = await shield.wrapModelCall(callModel, [
  { role: "system", content: trustedSystemPrompt },
  { role: "user", content: userText },
  { role: "tool", content: retrievedPageText },
]);

if (result.blocked) {
  // Blocked or held for review: callModel was not invoked.
  return { status: result.action, reason: result.reason };
}
return result.response;
```

`wrapModelCall` passes system and developer messages through as trusted configuration and screens user, document, and tool content. Tool and document roles retain their untrusted source even if a message includes a conflicting `source` field. A `sanitize` decision replaces only matched spans before the model adapter runs. A `block` or `escalate` decision prevents the adapter from being called. For full decisions and sanitized text without an adapter, use `screenPrompt` or `screenMessages` from `src/policy-engine.js`.

**Attach provenance in trusted application code.** Never let a browser client decide that retrieved content is a user message. Keep developer/system configuration separate from user, document, and tool text. This demo's adapter accepts string message content; extend the boundary carefully for multimodal or structured tool payloads.

## Outcomes and policy

The editable policy selects one of four outcomes for each finding:

- `allow` — pass the content through.
- `block` — do not hand it to the model.
- `sanitize` — remove only a detected span and pass the remaining text through.
- `escalate` — hold the content for a human review step.

Category actions and per-source overrides are in `policy.example.json`. The browser console can edit and save the policy. For the command-line evaluator, copy this file, change it, and pass its path to the evaluator:

```bash
npm run eval
npm run eval -- ./my-policy.json
```

The evaluator prints attack detections, false positives, misses, and per-case outcomes. It does not hide misses or turn them into a failing build, because the report is meant to support inspection and policy tuning.

## Evaluation set

`src/evaluation.js` contains labeled direct-user attacks, indirect document/tool attacks, obfuscated protected values, and legitimate requests that mention similar concepts. The score is calculated from the active policy and the 34 hand-written examples each time the page loads or the evaluator runs.

The fixture score is not a security guarantee. Regex and normalization checks are useful guardrails, but they do not understand every paraphrase or encoding. Add examples from your application, examine false positives, and red-team misses before relying on a policy.

## Data handling and limits

- The demo has no backend, analytics, model provider, or remote logging.
- The supplied protected strings are fake markers. Do not put live secrets in the browser policy editor or local storage.
- The in-memory decision log stores a short preview with detected spans redacted. It is cleared when the page session ends.
- Base64, hexadecimal, HTML entity, URL, Unicode compatibility, case, spacing, punctuation, and a small leetspeak mapping are checked. This is not general deobfuscation.
- The policy is passed to the middleware separately. Content under inspection is never parsed as policy configuration.
- Production deployments need server-side secret handling, authenticated reviewer workflows, structured content support, monitoring and retention controls, and a broader application-specific benchmark.

See [docs/POLICY.md](docs/POLICY.md) for the policy model and [SECURITY.md](SECURITY.md) for responsible security reporting.
