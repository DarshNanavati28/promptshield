# Policy model

## Provenance

Every screened value is tagged as `user`, `document`, or `tool`. Retrieved documents and tool responses are untrusted data. Their text may be analyzed, sanitized, blocked, or escalated, but it is never executed as policy and cannot update the policy object.

Application code must attach source labels. The middleware forces `role: "tool"` and `role: "document"` to their untrusted sources even if a message carries a `source` property. System and developer messages are treated as trusted configuration and pass through without screening; do not put user-controlled text into those roles.

## Categories

| Category | Example intent |
| --- | --- |
| `instruction_override` | Replace or bypass system/developer rules or expose hidden instructions |
| `protected_disclosure` | Request credentials, hidden context, or internal prompts |
| `external_exfiltration` | Pair sensitive information with a URL, domain, email address, webhook, or outside destination |
| `protected_value` | Match a value configured in `protectedValues`, including normalized or simply encoded forms |
| `suspicious_context` | Address an assistant with a suspicious instruction inside untrusted content |

Each category has a fallback action. `sourceOverrides` can make a category stricter or more permissive by source. Outcomes are ranked `allow < sanitize < escalate < block` when several findings apply. A block therefore wins over a sanitize finding in the same input.

## Sanitization

Sanitization removes the spans identified by findings, merges overlapping spans, and preserves the rest of the input. The middleware escalates a sanitized protected-value match if the match was detected in a whole-text encoding and its precise source span cannot be isolated. This prevents the sanitizer from deleting unrelated content by guesswork.

## Protected values

Values are compared after Unicode NFKC, case folding, punctuation/spacing removal, and a small digit-to-letter substitution. The gate also checks URL decoding, HTML entities, Base64 tokens, and hexadecimal tokens. These methods are intentionally limited; they are not cryptographic secret scanners.

## Operational guidance

- Keep real protected values in a server-side secret store and use an appropriate keyed fingerprint or secure matching service in production.
- Treat action choice and reviewer escalation as application-level controls. This demo records reasons but does not implement an approval queue.
- Keep policy changes authenticated, reviewed, and versioned outside user-controlled content.
- Extend the benchmark with application data, benign near-misses, indirect retrieval sources, and obfuscation variants. Report false positives and missed attacks as separate counts.
