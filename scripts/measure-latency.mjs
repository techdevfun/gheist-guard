// Latency measurement: evaluate the planted fixture in-process and
// report median + p95 per-repository scan time. No network involved.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { evaluateRest } from "../dist/rules.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const input = JSON.parse(
  readFileSync(path.join(root, "tests", "fixtures", "planted-rest.json"), "utf8"),
);
const N = 500;
const times = [];
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  evaluateRest(input);
  times.push(performance.now() - t0);
}
times.sort((a, b) => a - b);
const median = times[Math.floor(N / 2)];
const p95 = times[Math.floor(N * 0.95)];
console.log(`iterations: ${N}`);
console.log(`median_ms: ${median.toFixed(4)}`);
console.log(`p95_ms: ${p95.toFixed(4)}`);
