import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const data = path.join(repo, "data", "rq2");
const checks = [];
const fail = (name, detail) => { checks.push({ name, status: "failed", detail }); throw new Error(`${name}: ${detail}`); };
const pass = (name, detail) => checks.push({ name, status: "passed", detail });

const source = fs.readFileSync(path.join(repo, "src", "pathscope_modular_v2.py"));
const sourceHash = crypto.createHash("sha256").update(source).digest("hex");
if (sourceHash !== "4d5fa402cf40f8acd9aa891b9ac644ad1c86fbda53aec5185edae3a0120f1fc9") {
  fail("Archived diagnosis core", `Unexpected checksum: ${sourceHash}`);
}
pass("Archived diagnosis core", "Checksum matches the AutoDL two-module ablation report");

function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ""; }
    else if (c === '\n') { row.push(field.replace(/\r$/, "")); rows.push(row); row = []; field = ""; }
    else field += c;
  }
  if (field.length || row.length) { row.push(field.replace(/\r$/, "")); rows.push(row); }
  const header = rows.shift();
  return rows.filter(r => r.some(x => x !== "")).map(r => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""])));
}

const csv = rel => parseCsv(fs.readFileSync(path.join(repo, rel), "utf8").replace(/^\uFEFF/, ""));
const jsonl = rel => fs.readFileSync(path.join(repo, rel), "utf8").trim().split(/\r?\n/).filter(Boolean).map(JSON.parse);
const keyIndex = (rows, makeKey, name) => {
  const map = new Map();
  for (const row of rows) {
    const k = makeKey(row);
    if (map.has(k)) fail(`${name} uniqueness`, `duplicate ${k}`);
    map.set(k, row);
  }
  return map;
};
const approx = (a, b, eps = 1e-12) => Math.abs(Number(a) - Number(b)) <= eps;

const manifest = csv("data/rq2/manifest.csv");
const labels = csv("data/rq2/annotation/reference_labels.csv");
const predictions = csv("data/rq2/predictions/predictions.csv");
const m = keyIndex(manifest, r => r.trace_id, "manifest");
const l = keyIndex(labels, r => r.trace_id, "labels");
const p = keyIndex(predictions, r => `${r.trace_id}\u0000${r.method}`, "predictions");
if (m.size !== 748 || l.size !== 748) fail("RQ2 manifest size", `${m.size}/${l.size}`);
if ([...m.keys()].some(k => !l.has(k))) fail("RQ2 label join", "manifest/label ID mismatch");
pass("RQ2 manifest and label join", "748 unique trace IDs");

const groups = ["InjecAgent", "Conversational Attack", "Important Instructions"];
const main = Object.fromEntries(groups.map(g => [g, manifest.filter(r => r.main_group === g).map(r => r.trace_id).sort()]));
const ablation = manifest.filter(r => r.ablation_540 === "true").map(r => r.trace_id).sort();
if (main.InjecAgent.length !== 240 || main["Conversational Attack"].length !== 180 || main["Important Instructions"].length !== 208 || ablation.length !== 540) {
  fail("RQ2 scope sizes", JSON.stringify(Object.fromEntries(groups.map(g => [g, main[g].length]))));
}
pass("RQ2 scope sizes", "main=240+180+208; ablation=540");

const mainMethods = ["Tool-Name Match", "Full PathScope"];
const ablationMethods = ["Full PathScope", "w/o TRPV", "w/o GCES"];
const required = new Set();
for (const ids of Object.values(main)) for (const id of ids) for (const method of mainMethods) required.add(`${id}\u0000${method}`);
for (const id of ablation) for (const method of ablationMethods) required.add(`${id}\u0000${method}`);
if (p.size !== required.size || [...required].some(k => !p.has(k))) fail("prediction scope", `actual=${p.size}, required=${required.size}`);
for (const k of required) {
  const pred = p.get(k), trace = m.get(pred.trace_id), label = l.get(pred.trace_id);
  if (pred.source_sha256 !== trace.source_sha256 || label.source_sha256 !== trace.source_sha256) fail("source hash join", pred.trace_id);
}
pass("Prediction scope and source hashes", `${p.size} unique trace-method predictions`);

const evidence = jsonl("data/rq2/evidence/tool_events.jsonl");
const evidenceIndex = keyIndex(evidence, r => r.trace_id, "tool evidence");
if (evidenceIndex.size !== 748 || [...m.keys()].some(id => !evidenceIndex.has(id))) fail("tool evidence coverage", `records=${evidenceIndex.size}`);
let eventCount = 0;
for (const [traceId, record] of evidenceIndex) {
  const events = Array.isArray(record.events) ? record.events : [];
  const byId = new Map();
  for (const event of events) {
    if (!event.event_id || byId.has(event.event_id)) fail("tool evidence event IDs", traceId);
    byId.set(event.event_id, event);
    eventCount++;
  }
  for (const event of events) {
    if (event.kind === "tool_executed") {
      const proposal = byId.get(event.proposal_event_id);
      if (!proposal || proposal.kind !== "tool_proposed") fail("tool execution linkage", event.event_id);
    }
    if (event.kind === "tool_result") {
      const execution = byId.get(event.execution_event_id);
      if (!execution || execution.kind !== "tool_executed") fail("tool result linkage", event.event_id);
      const proposalId = event.proposal_event_id || execution.proposal_event_id;
      const proposal = byId.get(proposalId);
      if (!proposal || proposal.kind !== "tool_proposed") fail("tool result proposal linkage", event.event_id);
    }
  }
}
pass("Structural tool-event linkage", `748 evidence records and ${eventCount} linked events`);

function metrics(scope, method, dim, ids) {
  const matrix = new Map();
  const add = (a, b) => matrix.set(`${a}|${b}`, (matrix.get(`${a}|${b}`) ?? 0) + 1);
  for (const id of ids) {
    const ref = l.get(id)[dim];
    if (ref === "true" || ref === "false") add(ref, p.get(`${id}\u0000${method}`)[dim]);
  }
  const count = (a, b) => matrix.get(`${a}|${b}`) ?? 0;
  const known = [...matrix.values()].reduce((a, b) => a + b, 0);
  const correct = count("true", "true") + count("false", "false");
  const unknown = count("true", "unknown") + count("false", "unknown");
  const f1 = label => {
    let size = 0;
    for (const [k, n] of matrix) {
      const [a, b] = k.split("|");
      size += n * ((a === label ? 1 : 0) + (b === label ? 1 : 0));
    }
    return size ? 2 * count(label, label) / size : 0;
  };
  return { scope, method, dimension: dim, total: ids.length, reference_known: known,
    reference_unknown: ids.length - known, correct, prediction_covered: known - unknown,
    prediction_unknown: unknown, coverage: (known - unknown) / known,
    accuracy: correct / known, macro_f1: (f1("true") + f1("false")) / 2 };
}

const frozen4 = csv("data/rq2/tables/paper_table4_diagnosis.csv");
const recomputed4 = [];
for (const group of groups) for (const method of mainMethods) for (const dim of ["C", "G"]) recomputed4.push(metrics(group, method, dim, main[group]));
for (const row of recomputed4) {
  const frozen = frozen4.find(x => x.scope === row.scope && x.method === row.method && x.dimension === row.dimension);
  if (!frozen || !approx(frozen.accuracy, row.accuracy) || !approx(frozen.macro_f1, row.macro_f1) || Number(frozen.reference_known) !== row.reference_known) fail("paper Table 4", JSON.stringify(row));
}
pass("Paper Table 4 recomputation", "12 rows match frozen Accuracy, Macro-F1, and denominators");

const frozen5 = csv("data/rq2/tables/paper_table5_ablation.csv");
for (const method of ablationMethods) for (const dim of ["C", "G"]) {
  const row = metrics("Ablation 540", method, dim, ablation);
  const frozen = frozen5.find(x => x.method === method && x.dimension === dim);
  if (!frozen || !approx(frozen.accuracy, row.accuracy) || !approx(frozen.macro_f1, row.macro_f1) || Number(frozen.reference_known) !== row.reference_known) fail("paper Table 5", JSON.stringify(row));
}
pass("Paper Table 5 recomputation", "6 rows match frozen Accuracy, Macro-F1, and denominators");

const judges = jsonl("data/rq2/annotation/judge_decisions.jsonl");
const judge = keyIndex(judges, r => r.trace_id, "blind review");
let known = 0, knownAgree = 0, allDisagree = 0, unknown = 0;
const disagreementIds = new Set();
for (const [id, reference] of l) {
  const j = judge.get(id)?.label?.toLowerCase();
  if (!j) fail("blind review coverage", id);
  if (reference.C === "unknown") unknown++;
  else { known++; if (j === reference.C) knownAgree++; }
  if (j !== reference.C) { allDisagree++; disagreementIds.add(id); }
}
if (judges.length !== 748 || known !== 707 || unknown !== 41 || knownAgree !== 697 || allDisagree !== 19) fail("C blind review counts", JSON.stringify({ judges: judges.length, known, unknown, knownAgree, allDisagree }));
pass("C blind review counts", "697/707 determinate agreement (98.6% rounded); 19/748 total disagreements");

const adjudications = csv("data/rq2/annotation/adjudication_audit_19.csv");
if (adjudications.length !== 19 || adjudications.some(r => r.final_C.toLowerCase() !== r.rule_reference.toLowerCase()) || adjudications.some(r => !disagreementIds.has(r.trace_id))) fail("human adjudication", "rows or labels do not match disagreement set");
pass("Human adjudication audit", "19 disagreements; all final labels retain the reference label");

const table1 = csv("data/rq1/table1_rq1_coverage.csv");
const table2 = csv("data/rq1/table2_rq1_effectiveness.csv");
const table3 = csv("data/rq1/table3_rq1_joint.csv");
for (const row of table1.filter(r => r.group)) if (!approx(Number(row.scored_both) / Number(row.traces) * 100, Number(row.coverage_percent), 0.0051)) fail("paper Table 1 arithmetic", JSON.stringify(row));
const total1 = table1.find(r => r.attack_method === "Total");
if (Number(total1.traces) !== 660 || Number(total1.scored_both) !== 610 || !approx(610 / 660 * 100, Number(total1.coverage_percent), 0.0051)) fail("paper Table 1 total", JSON.stringify(total1));
for (const row of table3) {
  const total = ["both", "attack_only", "task_only", "neither"].reduce((s, k) => s + Number(row[k]), 0);
  if (total !== Number(row.pairs)) fail("paper Table 3 counts", JSON.stringify(row));
  const effect = table2.find(x => x.attack_method === row.attack_method && x.group === row.group);
  if (Number(effect.attack_successes) !== Number(row.both) + Number(row.attack_only) || Number(effect.user_task_successes) !== Number(row.both) + Number(row.task_only)) fail("paper Tables 2/3 join", row.group);
  if (!approx(Number(effect.attack_successes) / Number(effect.pairs) * 100, Number(effect.asr_percent), 0.0051) || !approx(Number(effect.user_task_successes) / Number(effect.pairs) * 100, Number(effect.utility_percent), 0.0051)) fail("paper Table 2 rates", row.group);
}
pass("Paper Tables 1-3 arithmetic", "660 traces, 610 dual-scored, and all paired counts/rates are internally consistent");

for (const traceId of ["D04__A0", "D29__A0"]) {
  const item = JSON.parse(fs.readFileSync(path.join(repo, "cases", `${traceId}.json`), "utf8"));
  const eventIds = new Set(evidenceIndex.get(traceId).events.map(event => event.event_id));
  if (item.case_id !== traceId || item.record_type !== "sanitized_summary" || !item.events.length ||
      !item.events.every(event => eventIds.has(event.id))) fail("Section 6.3 case evidence", traceId);
  if (l.get(traceId).G !== String(item.reference_G)) fail("Section 6.3 case reference", traceId);
  for (const [method, value] of Object.entries(item.predictions_G)) {
    if (p.get(`${traceId}\u0000${method}`)?.G !== String(value)) fail("Section 6.3 case prediction", `${traceId} / ${method}`);
  }
}
pass("Section 6.3 case evidence", "Both summaries match the event IDs, G references, and predictions");

console.log(JSON.stringify({ status: "passed", checks }, null, 2));

