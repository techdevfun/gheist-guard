// False-positive probe: run the rule set over recorded legitimate
// branches + workflows and report the counts. Expected: 0 CONFIRMED.
// Any SUSPECT must be explainable (see README probe table).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { evaluateRest } from "../dist/rules.js";
import { computeVerdict } from "../dist/verdict.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const branches = JSON.parse(
  readFileSync(path.join(root, "tests", "fixtures", "fp-branches.json"), "utf8"),
).branches;
const legit = JSON.parse(
  readFileSync(path.join(root, "tests", "fixtures", "legit-rest.json"), "utf8"),
);

const input = {
  repo: "probe/legitimate",
  branches: branches.map((name) => ({ name })),
  workflows: legit.workflows,
};
const findings = evaluateRest(input);
console.log(`branches: ${branches.length}`);
console.log(`workflows: ${legit.workflows.length}`);
console.log(`verdict: ${computeVerdict(findings)}`);
console.log(`findings: ${findings.length}`);
for (const f of findings) {
  console.log(`  [${f.rule}] ${f.evidence}`);
}
