import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_POLICY } from "../src/policy-engine.js";
import { evaluateCorpus } from "../src/evaluation.js";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const policyPath = process.argv[2];
let policy = DEFAULT_POLICY;
if (policyPath) {
  try {
    policy = JSON.parse(await readFile(resolve(process.cwd(), policyPath), "utf8"));
  } catch (error) {
    process.stderr.write(`Could not read policy file: ${error.message}\n`);
    process.exit(2);
  }
}

const report = evaluateCorpus(policy);
const pct = (value) => value === null ? "n/a" : `${(value * 100).toFixed(1)}%`;
process.stdout.write(`PromptShield evaluation — ${report.policy.name} v${report.policy.version}\n`);
process.stdout.write(`${report.total} labeled examples (${report.malicious} malicious, ${report.legitimate} legitimate)\n\n`);
process.stdout.write(`Attacks detected: ${report.truePositives}/${report.malicious} (${pct(report.recall)})\n`);
process.stdout.write(`False positives:  ${report.falsePositives}/${report.legitimate} (${pct(report.falsePositiveRate)})\n`);
process.stdout.write(`Missed attacks:   ${report.falseNegatives}\n`);
process.stdout.write(`True negatives:   ${report.trueNegatives}\n`);
process.stdout.write(`Precision:        ${pct(report.precision)}\n\n`);
if (report.falsePositives) {
  process.stdout.write("FALSE POSITIVES\n");
  for (const item of report.cases.filter(({ falsePositive }) => falsePositive)) process.stdout.write(`  ${item.id} ${item.label} → ${item.outcome}: ${item.reason}\n`);
  process.stdout.write("\n");
}
if (report.falseNegatives) {
  process.stdout.write("MISSED ATTACKS\n");
  for (const item of report.cases.filter(({ missed }) => missed)) process.stdout.write(`  ${item.id} ${item.label} (${item.source}): ${item.text}\n`);
  process.stdout.write("\n");
}
process.stdout.write("Per-case outcomes\n");
for (const item of report.cases) {
  const marker = item.missed ? "MISS" : item.falsePositive ? "FALSE POSITIVE" : "ok";
  process.stdout.write(`  ${item.id} [${item.kind}] ${item.outcome.padEnd(8)} ${marker.padEnd(14)} ${item.label}\n`);
}
