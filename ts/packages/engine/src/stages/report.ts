/**
 * Report Generator — deterministic, no LLM needed.
 *
 * Faithful port of `src/threatforest/agents/report/{agent,verifier}.py`.
 *
 * Compiles all state files (scanner_context.json, threats.json,
 * attack_trees.json, ttp_mappings.json, mitigations.json) into a structured
 * Markdown report (`threat_model_report.md`) AND the UI data bundle
 * (`threatforest_data.json`). Both are written to the run's output dir
 * (run_dir/output, else <repo>/.threatforest/output).
 *
 * Parity is byte-for-byte critical: the on-disk `threatforest_data.json` is the
 * contract the UI consumes (see @threatforest/types ThreatForestDataSchema /
 * UiAttackTree), and the markdown sections are checked by verifyReportOutput.
 * Python f-string formatting (`:.2f`, `:.3f`, `.upper()`, `[:N]` slices,
 * `', '.join(...)`) is reproduced exactly.
 *
 * The workspace helper (`../workspace.js`) and its `resolveStateDir` /
 * `resolveOutputDir` already exist — imported, not recreated.
 */
import { basename } from 'node:path';
import {
  LocalFilesystemWorkspace,
  resolveStateDir,
  resolveOutputDir,
} from '../workspace.js';

const OUTPUT_FILE = 'threat_model_report.md';

// ---------------------------------------------------------------------------
// Python-formatting helpers (match f-string output character-for-character).
// ---------------------------------------------------------------------------

/** Mirror Python `dict.get(key, default)` for plain JSON objects. */
function get<T = unknown>(obj: Record<string, unknown> | undefined, key: string, fallback: T): T {
  if (!obj) return fallback;
  const v = obj[key];
  return v === undefined ? fallback : (v as T);
}

/**
 * Faithful CPython `f"{x:.Nf}"`: round-half-to-even on the EXACT IEEE-754 double
 * value. JS `Number.toFixed` rounds half ties differently (e.g. (0.125).toFixed(2)
 * === "0.13" but Python yields "0.12"); the markdown similarity column and the
 * data-bundle `reasoning` string are part of the byte-for-byte UI contract, so we
 * reproduce Python's rounding exactly via BigInt rational arithmetic.
 */
function pyFixed(x: number, n: number): string {
  if (!Number.isFinite(x)) return String(x);
  const neg = x < 0 || Object.is(x, -0);
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setFloat64(0, Math.abs(x));
  const bits = (BigInt(dv.getUint32(0)) << 32n) | BigInt(dv.getUint32(4));
  const expBits = Number((bits >> 52n) & 0x7ffn);
  const mantBits = bits & 0xfffffffffffffn;
  let mant: bigint;
  let e2: number;
  if (expBits === 0) {
    mant = mantBits; // subnormal
    e2 = -1074;
  } else {
    mant = mantBits | 0x10000000000000n;
    e2 = expBits - 1075;
  }
  if (mant === 0n) {
    return (0).toFixed(n);
  }
  // value = mant * 2^e2; scale (value * 10^n) to an integer numerator/denominator.
  let num: bigint;
  let den: bigint;
  if (e2 >= 0) {
    num = mant << BigInt(e2);
    den = 1n;
  } else {
    num = mant;
    den = 1n << BigInt(-e2);
  }
  num *= 10n ** BigInt(n);
  // q = round_half_even(num / den)
  let q = num / den;
  const r = num - q * den;
  const twice = r * 2n;
  if (twice > den) {
    q += 1n;
  } else if (twice === den && q % 2n === 1n) {
    q += 1n; // half → round to even
  }
  const sign = neg && q !== 0n ? '-' : '';
  let s = q.toString();
  if (n === 0) return sign + s;
  if (s.length <= n) s = '0'.repeat(n - s.length + 1) + s;
  const intPart = s.slice(0, s.length - n);
  const fracPart = s.slice(s.length - n);
  return `${sign}${intPart}.${fracPart}`;
}

/** Python `f"{x:.2f}"` — handles ints / non-numbers as 0.00. */
function fixed2(x: unknown): string {
  return pyFixed(typeof x === 'number' ? x : 0, 2);
}

/** Python `f"{x:.3f}"`. */
function fixed3(x: unknown): string {
  return pyFixed(typeof x === 'number' ? x : 0, 3);
}

/** Python `str.upper()` on a possibly-missing string. */
function upper(s: unknown): string {
  return typeof s === 'string' ? s.toUpperCase() : '';
}

/** Python `str[:n]` slice (only meaningful for strings). */
function slice(s: unknown, n: number): string {
  return typeof s === 'string' ? s.slice(0, n) : '';
}

/** Python `", ".join(list)` — coerces non-string members via String(). */
function joinComma(arr: unknown): string {
  if (!Array.isArray(arr)) return '';
  return arr.map((x) => (typeof x === 'string' ? x : String(x))).join(', ');
}

type JsonObj = Record<string, unknown>;

/**
 * Marker for a Python `float`-typed value. Python's `json` preserves the float
 * type, so a whole-number float renders as `0.0` / `1.0`, whereas JS has a
 * single number type and `JSON.stringify(0.0)` yields `"0"`. The data bundle's
 * `probability`, `reach_probability`, `confidence`, and `similarity` fields are
 * float-typed in the Python models, so we wrap them and render via `stringifyPy`
 * to keep `threatforest_data.json` byte-for-byte identical.
 */
class PyFloat {
  constructor(readonly value: number) {}
}

/** Wrap a numeric value as a Python float (non-numbers pass through unchanged). */
function pyFloat(v: unknown): unknown {
  return typeof v === 'number' && Number.isFinite(v) ? new PyFloat(v) : v;
}

/** Render a finite number the way Python's `repr(float)` / `json.dumps` does. */
function pyFloatRepr(n: number): string {
  if (Object.is(n, -0)) return '-0.0';
  // JS prints whole-value floats without a decimal; Python's float repr appends ".0".
  return Number.isInteger(n) ? `${n}.0` : String(n);
}

/**
 * `json.dumps(obj, indent=2, ensure_ascii=False)` faithful serializer, with
 * `PyFloat` sentinels rendered as Python floats. Mirrors Python's separators
 * (`": "` / `","` with newline+indent), which match `JSON.stringify(_, _, 2)`.
 */
function stringifyPy(value: unknown, indent = 0): string {
  const pad = '  '.repeat(indent);
  const padInner = '  '.repeat(indent + 1);

  if (value instanceof PyFloat) return pyFloatRepr(value.value);
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number') {
    // Plain JS numbers follow JS rules (ints stay ints) — matches Python ints.
    return Number.isFinite(value) ? String(value) : 'null';
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    const items = value.map((v) => `${padInner}${stringifyPy(v, indent + 1)}`);
    return `[\n${items.join(',\n')}\n${pad}]`;
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as JsonObj);
    if (entries.length === 0) return '{}';
    const items = entries.map(
      ([k, v]) => `${padInner}${JSON.stringify(k)}: ${stringifyPy(v, indent + 1)}`,
    );
    return `{\n${items.join(',\n')}\n${pad}}`;
  }

  return 'null';
}

/**
 * Port of `_read_json`: read text, scrub trailing-comma artifacts, parse.
 * Returns `{}` on any read/parse error (mirrors the Python except clause).
 */
function readJsonSafe(ws: LocalFilesystemWorkspace, key: string): JsonObj {
  try {
    const raw = ws.readText(key).replace(/,\n]/g, '\n]').replace(/,]/g, ']');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? (parsed as JsonObj) : {};
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------------------
// runReportGenerator
// ---------------------------------------------------------------------------

export async function runReportGenerator(repoPath: string, runDir?: string): Promise<string> {
  const stateDir = resolveStateDir(repoPath, runDir);
  const outputDir = resolveOutputDir(repoPath, runDir);
  const stateWs = new LocalFilesystemWorkspace(stateDir);

  const scanner = readJsonSafe(stateWs, 'scanner_context.json');
  const threatsData = readJsonSafe(stateWs, 'threats.json');
  const treesData = readJsonSafe(stateWs, 'attack_trees.json');
  const mappingsData = readJsonSafe(stateWs, 'ttp_mappings.json');
  const mitigationsData = readJsonSafe(stateWs, 'mitigations.json');

  const threats = get<JsonObj[]>(threatsData, 'threats', []);
  const trees = get<JsonObj[]>(treesData, 'attack_trees', []);
  const mappings = get<JsonObj[]>(mappingsData, 'ttp_mappings', []);
  const mitigations = get<JsonObj[]>(mitigationsData, 'mitigations', []);

  const totalSteps = trees.reduce((acc, t) => acc + get<unknown[]>(t, 'steps', []).length, 0);
  const projectName = basename(repoPath);

  const lines: string[] = ['# Threat Model Report', ''];

  // Executive Summary
  lines.push('## Executive Summary');
  lines.push(
    `This report covers ${threats.length} threats across ${trees.length} attack trees ` +
      `with ${totalSteps} attack steps, ` +
      `${mappings.length} TTP mappings, and ${mitigations.length} mitigations ` +
      `for the ${projectName} project.`,
  );
  lines.push('');

  // Project Context
  lines.push('## Project Context');
  lines.push(`- **Cloud Provider**: ${upper(get(scanner, 'cloud_provider', 'unknown'))}`);
  lines.push(`- **Tech Stack**: ${get(scanner, 'tech_stack', 'N/A')}`);
  lines.push(`- **Services**: ${joinComma(get(scanner, 'services', []))}`);
  lines.push(`- **Auth Mechanisms**: ${joinComma(get(scanner, 'auth_mechanisms', []))}`);
  lines.push(`- **Files Analyzed**: ${get<unknown[]>(scanner, 'files_analyzed', []).length}`);
  lines.push('');

  // Threats
  lines.push('## Threats');
  for (const t of threats) {
    // Python: t.get("priority") or t.get("severity") or "medium"
    const sev = get<unknown>(t, 'priority', undefined) || get<unknown>(t, 'severity', undefined) || 'medium';
    // Python: t.get("title") or t.get("name") or t.get("description", "")[:80]
    const title =
      get<unknown>(t, 'title', undefined) ||
      get<unknown>(t, 'name', undefined) ||
      slice(get(t, 'description', ''), 80);
    lines.push(`### ${get(t, 'id', '?')}: ${title}`);
    lines.push(`**Severity**: ${sev}`);
    const desc = get<unknown>(t, 'description', undefined);
    if (desc) {
      lines.push(`\n${desc}`);
    }
    // Python `if t.get("affected_components"):` — empty list is falsy.
    const affected = get<unknown>(t, 'affected_components', undefined);
    if (Array.isArray(affected) ? affected.length > 0 : Boolean(affected)) {
      lines.push(`\n**Affected Components**: ${joinComma(affected)}`);
    }
    lines.push('');
  }

  // Attack Trees
  lines.push('## Attack Trees');
  for (const tree of trees) {
    const goal = get(tree, 'root_goal', '');
    const steps = get<JsonObj[]>(tree, 'steps', []);
    lines.push(`### ${get(tree, 'id', '?')}: ${goal}`);
    lines.push(`Steps: ${steps.length}`);
    for (const s of steps.slice(0, 10)) {
      lines.push(`- ${get(s, 'description', '')}`);
    }
    if (steps.length > 10) {
      lines.push(`- ... and ${steps.length - 10} more steps`);
    }
    lines.push('');
  }

  // TTP Mappings
  lines.push('## TTP Mappings');
  lines.push('| Attack Step | Technique | Name | Framework | Similarity |');
  lines.push('|-------------|-----------|------|-----------|------------|');
  for (const m of mappings) {
    // Python: m.get("attack_step_id", m.get("attack_step_description", ""))[:50]
    const stepRaw =
      'attack_step_id' in m ? m['attack_step_id'] : get(m, 'attack_step_description', '');
    const step = slice(stepRaw, 50);
    const fw = upper(get(m, 'framework', 'attack'));
    lines.push(
      `| ${step} | ${get(m, 'technique_id', '')} | ${get(m, 'technique_name', '')} | ${fw} | ${fixed2(get(m, 'similarity_score', 0))} |`,
    );
  }
  lines.push('');

  // Mitigations — grouped by remediation type
  lines.push('## Mitigations');

  const REMEDIATION_LABELS: Record<string, string> = {
    quick_win: 'Quick Wins',
    short_term: 'Short Term',
    medium_term: 'Medium Term',
    long_term: 'Long Term',
    monitoring: 'Monitoring & Detection',
  };
  const REMEDIATION_ORDER = ['quick_win', 'short_term', 'medium_term', 'long_term', 'monitoring'];

  // Summary table — sorted by priority (Python: m.get("priority", 99), stable sort).
  lines.push('| Priority | Mitigation | Remediation | Technique |');
  lines.push('|----------|-----------|-------------|-----------|');
  const sortedMits = stableSortByPriority(mitigations);
  for (const m of sortedMits) {
    const pri = get(m, 'priority', '?');
    const rtype = get(m, 'remediation_type', '');
    // Python: REMEDIATION_LABELS.get(rtype, rtype or "—")
    const label = rtype in REMEDIATION_LABELS ? REMEDIATION_LABELS[rtype] : rtype || '—';
    const text = slice(get(m, 'mitigation_text', ''), 80);
    const tid = get(m, 'technique_id', '');
    lines.push(`| ${pri} | ${text} | ${label} | ${tid} |`);
  }
  lines.push('');

  // Detailed sections grouped by remediation type.
  // Python uses a defaultdict + `.pop(rtype, [])`, then iterates the remaining
  // items in insertion order. We replicate with a Map keyed by remediation_type.
  const byRtype = new Map<string, JsonObj[]>();
  for (const m of sortedMits) {
    const rtype = get(m, 'remediation_type', 'other');
    const bucket = byRtype.get(rtype);
    if (bucket) bucket.push(m);
    else byRtype.set(rtype, [m]);
  }

  const emitMitigationDetail = (m: JsonObj): void => {
    const pri = get(m, 'priority', '?');
    lines.push(`#### [P${pri}] ${slice(get(m, 'mitigation_text', ''), 100)}`);
    const guidance = get<unknown>(m, 'implementation_guidance', undefined);
    if (guidance) {
      lines.push(`\n${guidance}`);
    }
    // Python `if m.get("evidence")` — an empty list is falsy, so no block.
    const evidence = get<unknown>(m, 'evidence', undefined);
    if (Array.isArray(evidence) && evidence.length > 0) {
      lines.push('\n**Evidence**:');
      for (const e of evidence) {
        const ev = (e ?? {}) as JsonObj;
        lines.push(`- [${get(ev, 'source_type', '')}] ${get(ev, 'source_ref', '')}: ${get(ev, 'relevance', '')}`);
      }
    }
    lines.push('');
  };

  // Ordered remediation buckets first (consuming them out of the map via delete,
  // matching Python's `by_rtype.pop(rtype, [])`).
  for (const rtype of REMEDIATION_ORDER) {
    const group = byRtype.get(rtype) ?? [];
    byRtype.delete(rtype);
    if (group.length === 0) continue;
    lines.push(`### ${rtype in REMEDIATION_LABELS ? REMEDIATION_LABELS[rtype] : rtype}`);
    for (const m of group) emitMitigationDetail(m);
  }

  // Any remaining without a recognized remediation_type (insertion order).
  for (const [rtype, group] of byRtype) {
    if (group.length === 0) continue;
    // Python: REMEDIATION_LABELS.get(rtype, rtype.replace("_", " ").title())
    const label = rtype in REMEDIATION_LABELS ? REMEDIATION_LABELS[rtype] : titleCase(rtype.replace('_', ' '));
    lines.push(`### ${label}`);
    for (const m of group) emitMitigationDetail(m);
  }

  // Coverage Summary
  lines.push('## Coverage Summary');
  lines.push(`- **Threats**: ${threats.length}`);
  lines.push(`- **Attack Trees**: ${trees.length}`);
  lines.push(`- **Attack Steps**: ${totalSteps}`);
  lines.push(`- **TTP Mappings**: ${mappings.length}`);
  const uniqueTechniques = new Set<unknown>();
  for (const m of mappings) {
    const tid = get<unknown>(m, 'technique_id', undefined);
    if (tid) uniqueTechniques.add(tid);
  }
  lines.push(`- **Unique Techniques**: ${uniqueTechniques.size}`);
  lines.push(`- **Mitigations**: ${mitigations.length}`);
  lines.push('');

  const report = lines.join('\n');
  new LocalFilesystemWorkspace(outputDir).writeText(OUTPUT_FILE, report);

  // Generate the UI data bundle + registry metadata.
  generateDataBundle(repoPath, runDir);

  return `${outputDir}/${OUTPUT_FILE}`;
}

// ---------------------------------------------------------------------------
// Sorting / casing helpers (Python parity).
// ---------------------------------------------------------------------------

/**
 * Python `sorted(mitigations, key=lambda m: m.get("priority", 99))`.
 * Python's sort is stable; JS Array.sort is stable in modern engines, but we
 * make the priority comparison explicit and keep equal-key order via index.
 */
function stableSortByPriority(mits: JsonObj[]): JsonObj[] {
  return mits
    .map((m, i) => ({ m, i }))
    .sort((a, b) => {
      const pa = numericPriority(get(a.m, 'priority', 99));
      const pb = numericPriority(get(b.m, 'priority', 99));
      if (pa !== pb) return pa - pb;
      return a.i - b.i;
    })
    .map((x) => x.m);
}

function numericPriority(v: unknown): number {
  return typeof v === 'number' ? v : 99;
}

/** Python `str.title()` for a single space-joined phrase (capitalize each word). */
function titleCase(s: string): string {
  return s.replace(/\w\S*/g, (w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
}

// ---------------------------------------------------------------------------
// Mermaid builder — port of `_steps_to_mermaid`.
// ---------------------------------------------------------------------------

/** Convert structured steps to a mermaid `graph TD` diagram. */
function stepsToMermaid(steps: JsonObj[], rootGoal: string): string {
  const out: string[] = ['graph TD'];

  // Word-wrap labels at 40 chars, joined with mermaid line breaks (\n).
  const label = (textIn: unknown): string => {
    const text = (typeof textIn === 'string' ? textIn : '')
      .replace(/"/g, "'")
      .replace(/\n/g, ' ')
      .trim();
    const words = text.split(/\s+/).filter((w) => w.length > 0);
    const result: string[] = [];
    let line = '';
    for (const w of words) {
      if (line.length + w.length > 40) {
        result.push(line);
        line = w;
      } else {
        line = line ? `${line} ${w}` : w;
      }
    }
    if (line) result.push(line);
    return result.join('\\n');
  };

  // Map step IDs to simple mermaid-safe IDs (no hyphens).
  const idMap: Record<string, string> = {};
  steps.forEach((step, i) => {
    const sid = get(step, 'id', '');
    idMap[sid] = `S${i}`;
  });

  // Root goal node.
  if (rootGoal) {
    out.push(`    GOAL["GOAL: ${label(rootGoal)}"]`);
  }

  // Identify root (fact) steps and leaf steps.
  const rootSteps = steps.filter((s) => !get(s, 'parent_id', ''));
  const childIds = new Set<string>();
  for (const s of steps) {
    const pid = get<string>(s, 'parent_id', '');
    if (pid) childIds.add(pid);
  }
  const leafSteps = steps.filter((s) => {
    const sid = get<string>(s, 'id', '');
    return !childIds.has(sid) && get<string>(s, 'parent_id', '');
  });

  for (const step of steps) {
    const sid = get<string>(step, 'id', '');
    const desc = get(step, 'description', sid);
    const safe = idMap[sid] ?? sid;
    // Python: _label(step.get("title") or desc)
    const titleOrDesc = get<unknown>(step, 'title', undefined) || desc;
    out.push(`    ${safe}["${label(titleOrDesc)}"]`);
  }

  // Edges: parent → child (top-down flow: fact at top, GOAL at bottom).
  for (const step of steps) {
    const pid = get<string>(step, 'parent_id', '');
    const sid = get<string>(step, 'id', '');
    if (pid) {
      const safeFrom = idMap[pid] ?? pid;
      const safeTo = idMap[sid] ?? sid;
      out.push(`    ${safeFrom} --> ${safeTo}`);
    }
  }

  // Connect leaf steps to GOAL at the bottom.
  if (rootGoal) {
    for (const step of leafSteps) {
      const sid = get<string>(step, 'id', '');
      const safe = idMap[sid] ?? sid;
      out.push(`    ${safe} --> GOAL`);
    }
    // If no leaf steps, connect root steps to GOAL as fallback.
    if (leafSteps.length === 0) {
      for (const step of rootSteps) {
        const sid = get<string>(step, 'id', '');
        const safe = idMap[sid] ?? sid;
        out.push(`    ${safe} --> GOAL`);
      }
    }
  }

  // Class definitions for node styling.
  out.push('    classDef goal fill:#ff6b6b,stroke:#c92a2a,color:#fff,stroke-width:2px');
  out.push('    classDef attack fill:#ffd43b,stroke:#f08c00,stroke-width:2px');
  out.push('    class GOAL goal');
  const allStepIds = steps.map((s) => idMap[get<string>(s, 'id', '')] ?? '');
  if (allStepIds.length > 0) {
    out.push(`    class ${allStepIds.join(',')} attack`);
  }

  return out.join('\n');
}

// ---------------------------------------------------------------------------
// UI attack-trees builder — port of `_build_attack_trees_for_ui`.
// ---------------------------------------------------------------------------

function buildAttackTreesForUi(stateWs: LocalFilesystemWorkspace, threats: JsonObj[]): JsonObj[] {
  const trees: JsonObj[] = [];
  const mappingsByStep: Record<string, JsonObj> = {};
  const mitigationsByStep: Record<string, JsonObj> = {};

  // attack_trees.json — Python uses read_json (no manual scrub); on error → [].
  let treeData: JsonObj[] = [];
  try {
    const parsed = JSON.parse(stateWs.readText('attack_trees.json')) as JsonObj;
    treeData = get<JsonObj[]>(parsed, 'attack_trees', []);
  } catch {
    treeData = [];
  }

  // ttp_mappings.json — Python uses read_text + scrub; on error → leave empty.
  try {
    const raw = stateWs.readText('ttp_mappings.json').replace(/,\n]/g, '\n]').replace(/,]/g, ']');
    const parsed = JSON.parse(raw) as JsonObj;
    for (const m of get<JsonObj[]>(parsed, 'ttp_mappings', [])) {
      mappingsByStep[get<string>(m, 'attack_step_id', '')] = m;
    }
  } catch {
    /* leave mappingsByStep empty */
  }

  // mitigations.json — Python uses read_text + scrub; also indexes also_applies_to.
  try {
    const raw = stateWs.readText('mitigations.json').replace(/,\n]/g, '\n]').replace(/,]/g, ']');
    const parsed = JSON.parse(raw) as JsonObj;
    for (const m of get<JsonObj[]>(parsed, 'mitigations', [])) {
      const sid = get<string>(m, 'attack_step_id', '');
      mitigationsByStep[sid] = m;
      for (const also of get<string[]>(m, 'also_applies_to', [])) {
        mitigationsByStep[also] = m;
      }
    }
  } catch {
    /* leave mitigationsByStep empty */
  }

  // Map threat_id → threat data (Python: t.get("id", t.get("threat_id", ""))).
  const threatMap: Record<string, JsonObj> = {};
  for (const t of threats) {
    const tid = 'id' in t ? get<string>(t, 'id', '') : get<string>(t, 'threat_id', '');
    if (tid) threatMap[tid] = t;
  }

  // Count trees per threat_id so we can disambiguate duplicates (Python Counter).
  const treeCountByThreat: Record<string, number> = {};
  for (const t of treeData) {
    const k = get<string>(t, 'threat_id', '');
    treeCountByThreat[k] = (treeCountByThreat[k] ?? 0) + 1;
  }
  const treeIndexByThreat: Record<string, number> = {};

  for (const tree of treeData) {
    const threatId = get<string>(tree, 'threat_id', '');
    const threat = threatMap[threatId] ?? {};
    const steps = get<JsonObj[]>(tree, 'steps', []);

    const ttcMappings: JsonObj[] = [];
    const treeMitigations: JsonObj[] = [];
    const attackStepsUi: JsonObj[] = [];

    // Build safe ID map (same scheme as stepsToMermaid).
    const idMap: Record<string, string> = {};
    steps.forEach((step, i) => {
      idMap[get<string>(step, 'id', '')] = `S${i}`;
    });

    for (const step of steps) {
      const sid = get<string>(step, 'id', '');
      const safeId = idMap[sid] ?? sid;
      const desc = get(step, 'description', '');
      const mapping = mappingsByStep[sid] ?? {};
      const mit = mitigationsByStep[sid];

      // Build attack_step entry. Python: title or desc.
      const title = get<unknown>(step, 'title', '');
      const stepEntry: JsonObj = {
        node_id: safeId,
        label: title || desc,
        description: desc,
        category: get(step, 'category', ''),
        // float-typed in Python — wrapped so whole values render as `0.0` / `1.0`.
        probability: pyFloat(get(step, 'probability', 0.0)),
        reach_probability: pyFloat(get(step, 'reach_probability', 0.0)),
        probability_rationale: get(step, 'probability_rationale', ''),
      };
      if (mit) {
        treeMitigations.push({
          name: get(mit, 'mitigation_text', ''),
          description: get(mit, 'implementation_guidance', ''),
          attack_step: safeId,
          priority: get(mit, 'priority', 3),
          technique_id: get(mit, 'technique_id', ''),
          remediation_type: get(mit, 'remediation_type', ''),
          evidence: get(mit, 'evidence', []),
        });
      }
      attackStepsUi.push(stepEntry);

      // Build TTC mapping entry (only when technique_id present).
      if (get<unknown>(mapping, 'technique_id', undefined)) {
        // Python: mapping.get("similarity_score", 0) — default is int 0 (not 0.0),
        // so an absent score renders `0`; a present float renders as a float.
        const simScore = get(mapping, 'similarity_score', 0);
        const simField =
          'similarity_score' in mapping ? pyFloat(simScore) : simScore;
        const reasoning =
          `Embedding similarity: ${fixed3(simScore)}` +
          (get<unknown>(mapping, 'reviewer_overrode_top1', undefined)
            ? ` (reviewer override: ${get(mapping, 'reviewer_reasoning', '')})`
            : '');
        ttcMappings.push({
          attack_step: desc,
          technique_id: get(mapping, 'technique_id', ''),
          technique_name: get(mapping, 'technique_name', ''),
          confidence: simField,
          similarity: simField,
          reasoning,
        });
      }
    }

    // Build a unique display threat_id when a threat has multiple trees.
    let displayThreatId: string;
    if ((treeCountByThreat[threatId] ?? 0) > 1) {
      const idx = (treeIndexByThreat[threatId] ?? 0) + 1;
      treeIndexByThreat[threatId] = idx;
      displayThreatId = `${threatId} [AttackTree - ${idx}]`;
    } else {
      displayThreatId = threatId;
    }

    // threat_category: threat.get("category") or .get("title") or .get("name") or .get("description","")[:80]
    const threatCategory =
      get<unknown>(threat, 'category', undefined) ||
      get<unknown>(threat, 'title', undefined) ||
      get<unknown>(threat, 'name', undefined) ||
      slice(get(threat, 'description', ''), 80);

    // threat_action: threat.get("title") or threat.get("name", "")
    const threatAction = get<unknown>(threat, 'title', undefined) || get(threat, 'name', '');

    // priority: threat.get("priority") or threat.get("severity", "medium")
    const priority = get<unknown>(threat, 'priority', undefined) || get(threat, 'severity', 'medium');

    trees.push({
      threat_id: displayThreatId,
      threat_category: threatCategory,
      threat_description: get(threat, 'description', ''),
      threat_statement: get(threat, 'description', ''),
      threat_action: threatAction,
      threatSource: get(threat, 'threat_source', ''),
      priority,
      attack_steps: attackStepsUi,
      ttc_mappings: ttcMappings,
      mitigations: treeMitigations,
      mapping_count: ttcMappings.length,
      root_goal: get(tree, 'root_goal', ''),
      mermaid_code: stepsToMermaid(steps, get<string>(tree, 'root_goal', '')),
    });
  }

  return trees;
}

// ---------------------------------------------------------------------------
// Short summary builder — port of `_build_short_summary`.
// ---------------------------------------------------------------------------

function buildShortSummary(
  projectName: string,
  scannerCtx: JsonObj,
  threatCount: number,
  highSev: number,
): string {
  const provider = upper(get(scannerCtx, 'cloud_provider', '') || '');
  const services = get<string[]>(scannerCtx, 'services', []);
  const techStack = get<string>(scannerCtx, 'tech_stack', '');

  const parts: string[] = [];

  // Opening — project name + provider + stack.
  let opener = projectName;
  if (provider) {
    opener += ` (${provider}`;
    if (techStack) {
      opener += `, ${techStack}`;
    }
    opener += ')';
  } else if (techStack) {
    opener += ` (${techStack})`;
  }
  parts.push(opener);

  // Key services (max 5).
  if (services.length > 0) {
    let svcStr = services.slice(0, 5).join(', ');
    if (services.length > 5) {
      svcStr += ` +${services.length - 5} more`;
    }
    parts.push(`using ${svcStr}`);
  }

  // Threat stats.
  if (threatCount) {
    let threatPart = `with ${threatCount} identified threat${threatCount !== 1 ? 's' : ''}`;
    if (highSev) {
      threatPart += ` (${highSev} high/critical)`;
    }
    parts.push(threatPart);
  }

  let summary = parts.join(' ') + '.';

  // Safety truncation at word boundary if somehow exceeds ~150 words.
  const words = summary.split(/\s+/);
  if (words.length > 150) {
    summary = words.slice(0, 150).join(' ') + '...';
  }

  return summary;
}

// ---------------------------------------------------------------------------
// Data bundle builder — port of `_generate_html_dashboard`.
//
// (The Python name references an "HTML dashboard" but the only side effect is
// writing `threatforest_data.json`; the HTML wrapper is no longer emitted.)
// ---------------------------------------------------------------------------

function generateDataBundle(repoPath: string, runDir?: string): void {
  const outputDir = resolveOutputDir(repoPath, runDir);
  const stateWs = new LocalFilesystemWorkspace(resolveStateDir(repoPath, runDir));
  const outputWs = new LocalFilesystemWorkspace(outputDir);

  if (!outputWs.exists(OUTPUT_FILE)) {
    return;
  }

  let threatCount = 0;
  let highSev = 0;
  let threats: JsonObj[] = [];
  let scannerCtx: JsonObj = {};

  // scanner_context.json — Python read_json; on error leave {}.
  try {
    scannerCtx = JSON.parse(stateWs.readText('scanner_context.json')) as JsonObj;
  } catch {
    scannerCtx = {};
  }

  // threats.json — Python read_json; on error leave [].
  try {
    const parsed = JSON.parse(stateWs.readText('threats.json')) as JsonObj;
    threats = get<JsonObj[]>(parsed, 'threats', []);
    threatCount = threats.length;
    // Python: t.get("priority", t.get("severity", "")).lower() in ("critical","high")
    highSev = threats.reduce((acc, t) => {
      const raw = 'priority' in t ? t['priority'] : get(t, 'severity', '');
      const sevStr = typeof raw === 'string' ? raw.toLowerCase() : '';
      return acc + (sevStr === 'critical' || sevStr === 'high' ? 1 : 0);
    }, 0);
  } catch {
    /* leave threats=[], counts 0 */
  }

  const projectName = basename(repoPath);
  // Python: scanner_ctx.get("description") or _build_short_summary(...)
  const shortSummary =
    (get<unknown>(scannerCtx, 'description', undefined) as string | undefined) ||
    buildShortSummary(projectName, scannerCtx, threatCount, highSev);

  const services5 = get<string[]>(scannerCtx, 'services', []).slice(0, 5);
  const metadata: JsonObj = {
    metadata: {
      generator: 'ThreatForest',
      version: '2.0',
    },
    project_info: {
      application_name: projectName,
      technologies: get<string[]>(scannerCtx, 'services', []),
      deployment_environment: get(scannerCtx, 'cloud_provider', ''),
      industry: get(scannerCtx, 'industry', ''),
      // Python: f"{provider.upper()} application using {tech_stack[:80]}. Services: {', '.join(services[:5])}."
      summary:
        `${upper(get(scannerCtx, 'cloud_provider', ''))} application using ${slice(get(scannerCtx, 'tech_stack', 'N/A'), 80)}. ` +
        `Services: ${services5.join(', ')}.`,
      short_summary: shortSummary,
    },
    status: 'complete',
    threat_count: threatCount,
    high_severity_count: highSev,
    extraction_summary: {
      total_threats: threatCount,
      high_severity_count: highSev,
    },
    threats,
    attack_trees: buildAttackTreesForUi(stateWs, threats),
    scanner_context: scannerCtx,
  };

  // Count total mappings across all UI attack trees.
  const attackTrees = get<JsonObj[]>(metadata, 'attack_trees', []);
  const totalMappings = attackTrees.reduce(
    (acc, t) => acc + get<unknown[]>(t, 'ttc_mappings', []).length,
    0,
  );

  metadata['mapping_summary'] = {
    total_mappings: totalMappings,
  };

  // Use the Python-float-faithful serializer (not writeJson) so float-typed
  // fields render as `0.0`/`1.0` to match `json.dumps(..., ensure_ascii=False)`.
  outputWs.writeText('threatforest_data.json', stringifyPy(metadata));
}

// ---------------------------------------------------------------------------
// verifyReportOutput — port of report/verifier.py.
// ---------------------------------------------------------------------------

const REQUIRED_SECTIONS = [
  'Executive Summary',
  'Project Context',
  'Threats',
  'Attack Trees',
  'TTP Mappings',
  'Mitigations',
  'Coverage Summary',
];

/**
 * Verify the report contains all required sections.
 * Returns `[passed, feedback]` — matching the Python `tuple[bool, str]`.
 *
 * Synchronous (reads one small file), matching the Python signature.
 */
export function verifyReportOutput(repoPath: string, runDir?: string): [boolean, string] {
  const outputDir = resolveOutputDir(repoPath, runDir);
  const outputWs = new LocalFilesystemWorkspace(outputDir);

  if (!outputWs.exists(OUTPUT_FILE)) {
    return [false, 'Report file does not exist'];
  }

  const content = outputWs.readText(OUTPUT_FILE);

  if (content.trim().length < 100) {
    return [false, 'Report is too short (< 100 chars)'];
  }

  const lower = content.toLowerCase();
  const missing = REQUIRED_SECTIONS.filter((s) => !lower.includes(s.toLowerCase()));
  if (missing.length > 0) {
    return [false, `Missing sections: ${missing.join(', ')}`];
  }

  return [true, 'Report is complete'];
}
