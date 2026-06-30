'use client';

/**
 * Export service for threat model data (TS port of
 * console-ui/src/utils/export-service.js).
 *
 * Provides comprehensive CSV and PDF export covering all threats, attack trees,
 * TTP mappings, and mitigations — mirroring the threat_model_report.md structure.
 *
 * The download helpers touch `document`/`Blob`/`URL`, and the PDF/CSV bundle
 * functions dynamically import jszip, so this module is client-only.
 */
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

// jspdf-autotable attaches `lastAutoTable` to the jsPDF instance at runtime but
// its bundled types don't augment the `jsPDF` interface. Declare it here so we
// can read `doc.lastAutoTable.finalY` without an `any` cast.
declare module 'jspdf' {
  interface jsPDF {
    lastAutoTable?: { finalY: number };
  }
}
import {
  aggregateMitigations,
  aggregateAllMitigations,
  getAffectedComponentsForTree,
  type ReportAttackTree,
  type ThreatRow,
  type AggregatedMitigation,
} from './mitigation-aggregator';
import { statusInfo } from './mitigation-status';

// ─── Input shape ──────────────────────────────────────────────
//
// The loose report-bundle summary blob (`threatforest_data.json` / the merged
// /data response). Attack trees use the same loose shape the aggregator reads.

/** The loose threat-model summary blob the exporters consume. */
export interface ThreatModelSummary {
  attack_trees?: ReportAttackTree[];
  threats?: ThreatRow[];
  project_info?: { application_name?: string; [key: string]: unknown };
  application_name?: string;
  extraction_summary?: { total_threats?: number; high_severity_count?: number; [key: string]: unknown };
  mapping_summary?: { total_mappings?: number; [key: string]: unknown };
  [key: string]: unknown;
}

/** The set of export sections the customise modal can toggle. */
export interface ExportSections {
  threats: boolean;
  attackSteps: boolean;
  ttp: boolean;
  mitigations: boolean;
}

/** A mitigation aggregated within a single tree, tagged with its threat id. */
type TaggedMitigation = AggregatedMitigation & { threatId: string };

/** A ttc_mapping tagged with its source threat id. */
type TaggedTtpMapping = {
  threatId: string;
  attack_step?: string;
  technique_id?: string;
  technique_name?: string;
  confidence?: number | null;
  [key: string]: unknown;
};

/**
 * Escape a CSV field value per RFC 4180, and neutralize spreadsheet formula
 * injection (CWE-1236). Threat/mitigation text is LLM-extracted from
 * user-controllable repo content, so a value beginning with = + - @ (or a
 * leading tab/CR) would be evaluated as a formula when the exported .csv is
 * opened in Excel/Sheets. Prefix any such field with a single quote so the
 * spreadsheet treats it as literal text.
 */
function escapeCsvField(value: unknown): string {
  if (value == null) return '';
  let str = String(value);
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }
  if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

// Backwards-compat shim — keep the local name so callers below don't change.
const getAffectedComponents = getAffectedComponentsForTree;

/**
 * Remediation type display labels.
 */
const REMEDIATION_LABELS: Record<string, string> = {
  quick_win: 'Quick Win',
  short_term: 'Short Term',
  medium_term: 'Medium Term',
  long_term: 'Long Term',
  monitoring: 'Monitoring & Detection',
};

/**
 * Priority display labels for numeric priorities.
 */
function priorityLabel(p: number | string | null | undefined): string {
  if (typeof p === 'number') return ['', 'Critical', 'High', 'Medium', 'Low'][p] || `P${p}`;
  return p || '';
}

// ─── CSV Export ───────────────────────────────────────────────

/**
 * Generate comprehensive CSV content from all threat model data.
 * Produces a mitigations-focused CSV with one row per mitigation across all threats.
 */
export function generateCsvContent(summaryData: ThreatModelSummary | null | undefined): string {
  if (!summaryData || typeof summaryData !== 'object') return '';

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) return '';

  const header = [
    'Threat ID',
    'Threat Category',
    'Threat Priority',
    'Mitigation Priority',
    'Mitigation',
    'Remediation Type',
    'Mapped TTP',
    'Attack Steps',
    'Implementation Guidance',
  ];
  const rows = [header.map(escapeCsvField).join(',')];

  for (const tree of attackTrees) {
    const threatId = tree.threat_id || '';
    const threatCategory = tree.threat_category || '';
    const threatPriority = tree.priority || '';
    const mitigations = aggregateMitigations(tree);

    for (const mit of mitigations) {
      const row = [
        escapeCsvField(threatId),
        escapeCsvField(threatCategory),
        escapeCsvField(threatPriority),
        escapeCsvField(priorityLabel(mit.priority)),
        escapeCsvField(mit.name),
        escapeCsvField(REMEDIATION_LABELS[mit.remediationType] || mit.remediationType || ''),
        escapeCsvField(mit.techniqueId || ''),
        escapeCsvField(mit.attackSteps.join('; ')),
        escapeCsvField(mit.description || ''),
      ];
      rows.push(row.join(','));
    }
  }

  return rows.join('\n');
}

/**
 * Trigger browser download of a CSV file.
 */
export function exportCsv(summaryData: ThreatModelSummary, filename?: string): void {
  const csvContent = generateCsvContent(summaryData);
  if (!csvContent) {
    alert('No threat model data available to export.');
    return;
  }
  downloadBlob(csvContent, 'text/csv;charset=utf-8;', filename || 'threat-model-report.csv');
}

// ─── Threats-only CSV ─────────────────────────────────────────

/**
 * Generate a threats-focused CSV with one row per threat.
 */
export function generateThreatsCsvContent(summaryData: ThreatModelSummary | null | undefined): string {
  if (!summaryData || typeof summaryData !== 'object') return '';

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  const threats = Array.isArray(summaryData.threats) ? summaryData.threats : [];
  if (attackTrees.length === 0) return '';

  const header = [
    'Threat ID', 'Category', 'Priority', 'Statement', 'Affected Components', 'Attack Steps',
  ];
  const rows = [header.map(escapeCsvField).join(',')];

  for (const tree of attackTrees) {
    const affected = getAffectedComponents(tree, threats);
    const steps = Array.isArray(tree.attack_steps) ? tree.attack_steps : [];
    const stepSummary = steps.map((s) => s.label || s.description || '').join('; ');
    rows.push([
      escapeCsvField(tree.threat_id || ''),
      escapeCsvField(tree.threat_category || ''),
      escapeCsvField(tree.priority || ''),
      escapeCsvField(tree.threat_statement || tree.threat_description || ''),
      escapeCsvField(affected.join(', ')),
      escapeCsvField(stepSummary),
    ].join(','));
  }

  return rows.join('\n');
}

/**
 * Download a threats-only CSV.
 */
export function exportThreatsCsv(summaryData: ThreatModelSummary, filename?: string): void {
  const content = generateThreatsCsvContent(summaryData);
  if (!content) { alert('No threat data available to export.'); return; }
  downloadBlob(content, 'text/csv;charset=utf-8;', filename || 'threats.csv');
}

/**
 * Generate a threats-only CSV that omits the per-step attack-tree summary —
 * one row per threat with category, priority, statement, and affected
 * components only. Useful for sharing the threat list with stakeholders who
 * don't need the kill-chain detail.
 */
export function generateThreatsOnlyCsvContent(summaryData: ThreatModelSummary | null | undefined): string {
  if (!summaryData || typeof summaryData !== 'object') return '';

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  const threats = Array.isArray(summaryData.threats) ? summaryData.threats : [];
  if (attackTrees.length === 0) return '';

  const header = ['Threat ID', 'Category', 'Priority', 'Statement', 'Affected Components'];
  const rows = [header.map(escapeCsvField).join(',')];

  for (const tree of attackTrees) {
    const affected = getAffectedComponents(tree, threats);
    rows.push([
      escapeCsvField(tree.threat_id || ''),
      escapeCsvField(tree.threat_category || ''),
      escapeCsvField(tree.priority || ''),
      escapeCsvField(tree.threat_statement || tree.threat_description || ''),
      escapeCsvField(affected.join(', ')),
    ].join(','));
  }

  return rows.join('\n');
}

/**
 * Download a threats-only CSV without the per-step attack-tree summary.
 */
export function exportThreatsOnlyCsv(summaryData: ThreatModelSummary, filename?: string): void {
  const content = generateThreatsOnlyCsvContent(summaryData);
  if (!content) { alert('No threat data available to export.'); return; }
  downloadBlob(content, 'text/csv;charset=utf-8;', filename || 'threats.csv');
}

// ─── Mitigations-only CSV ─────────────────────────────────────

/**
 * Generate a mitigations-focused CSV with one row per *unique* mitigation
 * (deduplicated across all attack trees the same way the dedup tab does).
 *
 * Threats / Attack Steps columns hold semicolon-separated lists when a
 * mitigation surfaced against more than one. Override status + comment are
 * included so external trackers (Jira, Linear) can carry the disposition.
 */
export function generateMitigationsCsvContent(summaryData: ThreatModelSummary | null | undefined): string {
  if (!summaryData || typeof summaryData !== 'object') return '';

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) return '';

  const threats = Array.isArray(summaryData.threats) ? summaryData.threats : [];
  const allMitigations = aggregateAllMitigations(attackTrees, threats);

  const header = [
    'Priority',
    'Status',
    'Status Comment',
    'Mitigation',
    'Remediation Type',
    'Mapped TTP',
    'Threats',
    'Attack Steps',
    'Implementation Guidance',
  ];
  const rows = [header.map(escapeCsvField).join(',')];

  allMitigations.sort((a, b) => {
    const pa = typeof a.priority === 'number' ? a.priority : 99;
    const pb = typeof b.priority === 'number' ? b.priority : 99;
    if (pa !== pb) return pa - pb;
    return (a.name || '').localeCompare(b.name || '');
  });

  for (const m of allMitigations) {
    const info = statusInfo(m.overrideStatus);
    rows.push([
      escapeCsvField(priorityLabel(m.priority)),
      escapeCsvField(info ? info.label : ''),
      escapeCsvField(m.overrideComment || ''),
      escapeCsvField(m.name || ''),
      escapeCsvField(REMEDIATION_LABELS[m.remediationType] || m.remediationType || ''),
      escapeCsvField(m.techniqueId || ''),
      escapeCsvField((m.threats || []).map((t) => t.id).filter(Boolean).join('; ')),
      escapeCsvField((m.attackSteps || []).join('; ')),
      escapeCsvField(m.description || ''),
    ].join(','));
  }

  return rows.join('\n');
}

/**
 * Download a mitigations-only CSV.
 */
export function exportMitigationsCsv(summaryData: ThreatModelSummary, filename?: string): void {
  const content = generateMitigationsCsvContent(summaryData);
  if (!content) { alert('No mitigation data available to export.'); return; }
  downloadBlob(content, 'text/csv;charset=utf-8;', filename || 'mitigations.csv');
}

// ─── Customisable export ──────────────────────────────────────
//
// Drives both the page-level and row-level "Customise export" modal.
// ``sections`` is a set of section keys; absent sections are dropped from
// the rendered output entirely. This replaces the old fixed-scope exports
// (Export All / Threats with steps / Threats only / Mitigations) which
// couldn't be combined.
//
// Section keys:
//   - "threats"       Threats overview table (one row per threat)
//   - "attackSteps"   Per-threat attack-step pages (the bulky one — opt-in)
//   - "ttp"           TTP mappings table
//   - "mitigations"   Mitigations table

export const EXPORT_SECTIONS: ReadonlyArray<keyof ExportSections> = [
  'threats',
  'attackSteps',
  'ttp',
  'mitigations',
];

/** Default section selection — Attack steps OFF to avoid 30-page reports. */
export const DEFAULT_SECTIONS: ExportSections = {
  threats: true,
  attackSteps: false,
  ttp: true,
  mitigations: true,
};

/**
 * Generate and download a section-customised PDF.
 *
 * Renders only the sections in ``sections``. Title page + executive summary
 * always render — they're essential framing and trivially short.
 */
export function exportCustomPdf(
  summaryData: ThreatModelSummary | null | undefined,
  sections: ExportSections,
  filename?: string,
): void {
  if (!summaryData || typeof summaryData !== 'object') {
    alert('No threat model data available to export.');
    return;
  }

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) {
    alert('No attack trees available to export.');
    return;
  }
  if (!sections || EXPORT_SECTIONS.every((s) => !sections[s])) {
    alert('Select at least one section to include in the report.');
    return;
  }

  try {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 14;

    const appName = summaryData.project_info?.application_name
      || summaryData.application_name || 'Threat Model';
    const ext = summaryData.extraction_summary || {};
    const map = summaryData.mapping_summary || {};
    const threats = summaryData.threats || [];

    // Aggregate once — both the executive summary counts and the optional
    // sections below need these arrays.
    const allMitigations: TaggedMitigation[] = [];
    const allTtpMappings: TaggedTtpMapping[] = [];
    for (const tree of attackTrees) {
      const treeMits = aggregateMitigations(tree);
      for (const mit of treeMits) {
        allMitigations.push({ ...mit, threatId: tree.threat_id || '' });
      }
      const ttcMappings = Array.isArray(tree.ttc_mappings) ? tree.ttc_mappings : [];
      for (const m of ttcMappings) {
        allTtpMappings.push({ ...m, threatId: tree.threat_id || '' });
      }
    }

    // ─── Title + Executive Summary ───
    doc.setFontSize(22);
    doc.setTextColor(...DARK_COLOR);
    doc.text('ThreatForest', pageWidth / 2, 35, { align: 'center' });
    doc.setFontSize(16);
    doc.text('Threat Model Report', pageWidth / 2, 45, { align: 'center' });
    doc.setFontSize(12);
    doc.setTextColor(100, 100, 100);
    doc.text(appName, pageWidth / 2, 57, { align: 'center' });
    doc.text(
      new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
      pageWidth / 2,
      65,
      { align: 'center' }
    );
    doc.setDrawColor(...THEME_COLOR);
    doc.setLineWidth(0.5);
    doc.line(margin, 72, pageWidth - margin, 72);

    doc.setFontSize(14);
    doc.setTextColor(...DARK_COLOR);
    doc.text('Executive Summary', margin, 82);

    const totalMitigations = attackTrees.reduce(
      (sum, tree) => sum + aggregateMitigations(tree).length,
      0
    );
    autoTable(doc, {
      startY: 87,
      head: [['Metric', 'Value']],
      body: [
        ['Total Threats', String(ext.total_threats ?? attackTrees.length)],
        ['High Severity', String(ext.high_severity_count ?? 0)],
        ['Attack Trees', String(attackTrees.length)],
        ['TTP Mappings', String(map.total_mappings ?? allTtpMappings.length)],
        ['Mitigations', String(totalMitigations)],
      ],
      theme: 'grid',
      headStyles: { fillColor: THEME_COLOR, fontSize: 10 },
      bodyStyles: { fontSize: 10 },
      columnStyles: { 0: { cellWidth: 60, fontStyle: 'bold' }, 1: { cellWidth: 40 } },
      margin: { left: margin, right: margin },
      tableWidth: 100,
    });

    // ─── Threats Overview ───
    if (sections.threats) {
      doc.addPage();
      doc.setFontSize(14);
      doc.setTextColor(...DARK_COLOR);
      doc.text('Threats Overview', margin, 20);
      const threatRows = attackTrees.map((tree) => {
        const affected = getAffectedComponents(tree, threats);
        return [
          tree.threat_id || '',
          tree.threat_category || '',
          tree.priority || '',
          tree.threat_statement || tree.threat_description || '',
          affected.slice(0, 3).join(', ') + (affected.length > 3 ? ` (+${affected.length - 3})` : ''),
        ];
      });
      autoTable(doc, {
        startY: 25,
        head: [['ID', 'Category', 'Priority', 'Statement', 'Affected Assets']],
        body: threatRows,
        theme: 'striped',
        headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
        bodyStyles: { fontSize: 7 },
        columnStyles: {
          0: { cellWidth: 20 },
          1: { cellWidth: 30 },
          2: { cellWidth: 18 },
          3: { cellWidth: 75 },
          4: { cellWidth: 35 },
        },
        margin: { left: margin, right: margin },
      });
    }

    // ─── Attack Steps ───
    // Compact rendering: trees flow back-to-back rather than each starting
    // a new page, with smaller fonts. The historical exportPdf added a page
    // break per tree which produced 30+ page reports for 10 threats.
    if (sections.attackSteps) {
      doc.addPage();
      let yPos = 20;
      doc.setFontSize(14);
      doc.setTextColor(...DARK_COLOR);
      doc.text('Attack Steps', margin, yPos);
      yPos += 8;

      const pageHeight = doc.internal.pageSize.getHeight();
      const ensureSpace = (needed: number) => {
        if (yPos + needed > pageHeight - 20) {
          doc.addPage();
          yPos = 20;
        }
      };

      for (const tree of attackTrees) {
        ensureSpace(20);
        doc.setFontSize(11);
        doc.setTextColor(...DARK_COLOR);
        doc.text(`${tree.threat_id || 'Unknown'} — ${tree.threat_category || ''}`, margin, yPos);
        yPos += 6;

        if (tree.priority) {
          doc.setFontSize(8);
          doc.setTextColor(80, 80, 80);
          doc.text(`Priority: ${tree.priority}`, margin, yPos);
          yPos += 5;
        }

        const steps = Array.isArray(tree.attack_steps) ? tree.attack_steps : [];
        if (steps.length === 0) {
          doc.setFontSize(8);
          doc.setTextColor(120, 120, 120);
          doc.text('(no attack steps)', margin, yPos);
          yPos += 6;
          continue;
        }

        autoTable(doc, {
          startY: yPos,
          head: [['Step ID', 'Label', 'Description']],
          body: steps.map((s) => [
            s.node_id || '',
            s.label || s.description || '',
            s.description || '',
          ]),
          theme: 'striped',
          headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
          bodyStyles: { fontSize: 7 },
          columnStyles: {
            0: { cellWidth: 22 },
            1: { cellWidth: 45 },
            2: { cellWidth: 'auto' },
          },
          margin: { left: margin, right: margin },
        });
        yPos = (doc.lastAutoTable?.finalY ?? yPos) + 6;
      }
    }

    // ─── TTP Mappings ───
    if (sections.ttp && allTtpMappings.length > 0) {
      doc.addPage();
      doc.setFontSize(14);
      doc.setTextColor(...DARK_COLOR);
      doc.text('TTP Mappings', margin, 20);
      autoTable(doc, {
        startY: 25,
        head: [['Threat', 'Attack Step', 'TTP ID', 'TTP Name', 'Confidence']],
        body: allTtpMappings.map((m) => [
          m.threatId || '',
          m.attack_step || '',
          m.technique_id || '',
          m.technique_name || '',
          m.confidence != null ? String(Math.round(m.confidence * 100) / 100) : '',
        ]),
        theme: 'striped',
        headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
        bodyStyles: { fontSize: 6.5 },
        columnStyles: {
          0: { cellWidth: 20 },
          1: { cellWidth: 30 },
          2: { cellWidth: 22 },
          3: { cellWidth: 60 },
          4: { cellWidth: 20 },
        },
        margin: { left: margin, right: margin },
      });
    }

    // ─── Mitigations ───
    if (sections.mitigations && allMitigations.length > 0) {
      doc.addPage();
      doc.setFontSize(14);
      doc.setTextColor(...DARK_COLOR);
      doc.text('Mitigations', margin, 20);
      const sorted = [...allMitigations].sort((a, b) => {
        const pa = typeof a.priority === 'number' ? a.priority : 99;
        const pb = typeof b.priority === 'number' ? b.priority : 99;
        return pa - pb;
      });
      autoTable(doc, {
        startY: 25,
        head: [['Priority', 'Mitigation', 'Remediation', 'Mapped TTP', 'Threat']],
        body: sorted.map((m) => [
          priorityLabel(m.priority),
          m.name || '',
          REMEDIATION_LABELS[m.remediationType] || m.remediationType || '',
          m.techniqueId || '',
          m.threatId || '',
        ]),
        theme: 'striped',
        headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
        bodyStyles: { fontSize: 6.5 },
        columnStyles: {
          0: { cellWidth: 18 },
          1: { cellWidth: 75 },
          2: { cellWidth: 25 },
          3: { cellWidth: 22 },
          4: { cellWidth: 20 },
        },
        margin: { left: margin, right: margin },
      });
    }

    addPdfFooter(doc, pageWidth, margin);
    doc.save(filename || 'threat-model-report.pdf');
  } catch (err) {
    alert(`PDF generation failed: ${(err as Error).message || 'Unknown error'}`);
  }
}

/**
 * Generate and download a section-customised CSV bundle.
 *
 * Single section selected → one ``.csv`` download. Multiple sections →
 * a ``.zip`` containing one CSV per section. JSZip is dynamically imported
 * so the (~25KB gzip) cost only lands when a multi-section CSV is actually
 * exported, not on every page load.
 *
 * Each CSV reuses the section's existing generator to keep field shapes
 * stable across the new modal and any external tooling that consumes them.
 */
export async function exportCustomCsvBundle(
  summaryData: ThreatModelSummary | null | undefined,
  sections: ExportSections,
  baseFilename?: string,
): Promise<void> {
  if (!summaryData || typeof summaryData !== 'object') {
    alert('No threat model data available to export.');
    return;
  }
  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) {
    alert('No threat model data available to export.');
    return;
  }

  const csvBySection: Record<string, string> = {};
  if (sections.threats) {
    csvBySection['threats.csv'] = generateThreatsOnlyCsvContent(summaryData);
  }
  if (sections.attackSteps) {
    // Reuse the existing threats-with-steps generator for the attack-step
    // CSV — the step list per threat is the load-bearing column there.
    csvBySection['attack-steps.csv'] = generateThreatsCsvContent(summaryData);
  }
  if (sections.ttp) {
    csvBySection['ttp-mappings.csv'] = generateTtpMappingsCsvContent(summaryData);
  }
  if (sections.mitigations) {
    csvBySection['mitigations.csv'] = generateMitigationsCsvContent(summaryData);
  }

  const entries = Object.entries(csvBySection).filter(([, body]) => Boolean(body));
  if (entries.length === 0) {
    alert('Select at least one section that has data to export.');
    return;
  }

  const stem = (baseFilename || 'threat-model').replace(/\.(csv|zip)$/i, '');

  if (entries.length === 1) {
    const [name, body] = entries[0]!;
    downloadBlob(body, 'text/csv;charset=utf-8;', `${stem}-${name}`);
    return;
  }

  // Multiple sections → zip them. Dynamic import keeps JSZip out of the
  // initial bundle for users who never multi-section export.
  const { default: JSZip } = await import('jszip');
  const zip = new JSZip();
  for (const [name, body] of entries) zip.file(name, body);
  const blob = await zip.generateAsync({ type: 'blob' });

  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${stem}.zip`;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Generate the TTP mappings CSV — one row per (threat × technique) pair.
 *
 * Pulled out as a named export so ``exportCustomCsvBundle`` can include
 * a TTP-only CSV when the user selects only that section. Mirrors the
 * shape of the TTP table in the PDF.
 */
export function generateTtpMappingsCsvContent(summaryData: ThreatModelSummary | null | undefined): string {
  if (!summaryData || typeof summaryData !== 'object') return '';
  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) return '';

  const header = ['Threat ID', 'Attack Step', 'TTP ID', 'TTP Name', 'Confidence'];
  const rows = [header.map(escapeCsvField).join(',')];

  for (const tree of attackTrees) {
    const ttp = Array.isArray(tree.ttc_mappings) ? tree.ttc_mappings : [];
    for (const m of ttp) {
      rows.push([
        escapeCsvField(tree.threat_id || ''),
        escapeCsvField(m.attack_step || ''),
        escapeCsvField(m.technique_id || ''),
        escapeCsvField(m.technique_name || ''),
        escapeCsvField(m.confidence != null ? String(Math.round(m.confidence * 100) / 100) : ''),
      ].join(','));
    }
  }
  return rows.join('\n');
}

// ─── ThreatForest Report bundle (.tfreport) ───────────────────

/** Arguments for {@link downloadThreatforestReport}. */
export interface DownloadThreatforestReportArgs {
  /** URL-encoded application id (v2 or legacy slug). */
  appId: string;
  /** When set, exports just that version. Omit for full-app. */
  versionId?: string;
  /** Send through to the server's query param. */
  includeScannerContext?: boolean;
  /** Override the server-supplied download filename. */
  filename?: string;
}

/**
 * Stream a ``.tfreport`` bundle from the server and trigger a browser
 * download. Used for both the per-version export (``versionId`` set) and
 * the full-application export (``versionId`` omitted).
 *
 * The actual bundle is built server-side; the client only orchestrates
 * the fetch and the temp-link download. Errors are surfaced as thrown
 * Errors so the caller can show them in an Alert.
 */
export async function downloadThreatforestReport({
  appId,
  versionId,
  includeScannerContext,
  filename,
}: DownloadThreatforestReportArgs): Promise<void> {
  if (!appId) throw new Error('appId is required to export a ThreatForest report.');

  const qs = new URLSearchParams({
    include_scanner_context: includeScannerContext ? 'true' : 'false',
  }).toString();
  const url = versionId
    ? `/api/applications/${encodeURIComponent(appId)}/versions/${encodeURIComponent(versionId)}/report?${qs}`
    : `/api/applications/${encodeURIComponent(appId)}/report?${qs}`;

  const response = await fetch(url);
  if (!response.ok) {
    // Try to surface the JSON ``detail`` field from FastAPI when present —
    // otherwise fall back to status text so the user has *something*.
    let detail = '';
    try {
      const body = (await response.json()) as { detail?: string };
      detail = body?.detail || '';
    } catch {
      // Non-JSON error body — ignore.
    }
    throw new Error(
      detail || `Failed to export report (HTTP ${response.status}).`
    );
  }

  // Prefer the server-supplied filename when the caller didn't override.
  // Falls back to a generic name if Content-Disposition is missing.
  const blob = await response.blob();
  let downloadName = filename;
  if (!downloadName) {
    const disposition = response.headers.get('content-disposition') || '';
    const match = /filename="?([^"]+)"?/.exec(disposition);
    downloadName = (match && match[1]) || 'threatforest-report.tfreport';
  }

  const blobUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = downloadName;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(blobUrl);
}

// ─── Shared download helper ───────────────────────────────────

function downloadBlob(content: string, mimeType: string, filename: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// ─── PDF Export ───────────────────────────────────────────────

/**
 * Blue theme color used for PDF headers.
 */
const THEME_COLOR: [number, number, number] = [41, 128, 185];
const DARK_COLOR: [number, number, number] = [44, 62, 80];

/**
 * Generate and download a comprehensive PDF threat model report.
 *
 * Structure mirrors threat_model_report.md:
 *   1. Title + Executive Summary
 *   2. Threats Overview table
 *   3. Attack Trees (per-tree sections with steps)
 *   4. TTP Mappings table (all trees)
 *   5. Mitigations table (all trees)
 */
export function exportPdf(summaryData: ThreatModelSummary | null | undefined, filename?: string): void {
  if (!summaryData || typeof summaryData !== 'object') {
    alert('No threat model data available to export.');
    return;
  }

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) {
    alert('No attack trees available to export.');
    return;
  }

  try {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 14;
    const contentWidth = pageWidth - margin * 2;

    const appName = summaryData.project_info?.application_name
      || summaryData.application_name || 'Threat Model';
    const ext = summaryData.extraction_summary || {};
    const map = summaryData.mapping_summary || {};
    const threats = summaryData.threats || [];

    // Collect all mitigations across all trees for the mitigations section
    const allMitigations: TaggedMitigation[] = [];
    const allTtpMappings: TaggedTtpMapping[] = [];
    for (const tree of attackTrees) {
      const treeMits = aggregateMitigations(tree);
      for (const mit of treeMits) {
        allMitigations.push({ ...mit, threatId: tree.threat_id || '' });
      }
      const ttcMappings = Array.isArray(tree.ttc_mappings) ? tree.ttc_mappings : [];
      for (const m of ttcMappings) {
        allTtpMappings.push({ ...m, threatId: tree.threat_id || '' });
      }
    }

    // ─── Page 1: Title + Executive Summary ───
    doc.setFontSize(22);
    doc.setTextColor(...DARK_COLOR);
    doc.text('ThreatForest', pageWidth / 2, 35, { align: 'center' });
    doc.setFontSize(16);
    doc.text('Threat Model Report', pageWidth / 2, 45, { align: 'center' });

    doc.setFontSize(12);
    doc.setTextColor(100, 100, 100);
    doc.text(appName, pageWidth / 2, 57, { align: 'center' });
    doc.text(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }), pageWidth / 2, 65, { align: 'center' });

    // Divider line
    doc.setDrawColor(...THEME_COLOR);
    doc.setLineWidth(0.5);
    doc.line(margin, 72, pageWidth - margin, 72);

    // Executive Summary
    doc.setFontSize(14);
    doc.setTextColor(...DARK_COLOR);
    doc.text('Executive Summary', margin, 82);

    const totalMitigations = attackTrees.reduce(
      (sum, tree) => sum + aggregateMitigations(tree).length, 0
    );

    const summaryRows = [
      ['Total Threats', String(ext.total_threats ?? attackTrees.length)],
      ['High Severity', String(ext.high_severity_count ?? 0)],
      ['Attack Trees', String(attackTrees.length)],
      ['TTP Mappings', String(map.total_mappings ?? allTtpMappings.length)],
      ['Mitigations', String(totalMitigations)],
    ];

    autoTable(doc, {
      startY: 87,
      head: [['Metric', 'Value']],
      body: summaryRows,
      theme: 'grid',
      headStyles: { fillColor: THEME_COLOR, fontSize: 10 },
      bodyStyles: { fontSize: 10 },
      columnStyles: {
        0: { cellWidth: 60, fontStyle: 'bold' },
        1: { cellWidth: 40 },
      },
      margin: { left: margin, right: margin },
      tableWidth: 100,
    });

    // ─── Page 2: Threats Overview ───
    doc.addPage();
    doc.setFontSize(14);
    doc.setTextColor(...DARK_COLOR);
    doc.text('Threats Overview', margin, 20);

    const threatRows = attackTrees.map((tree) => {
      const affected = getAffectedComponents(tree, threats);
      return [
        tree.threat_id || '',
        tree.threat_category || '',
        tree.priority || '',
        tree.threat_statement || tree.threat_description || '',
        affected.slice(0, 3).join(', ') + (affected.length > 3 ? ` (+${affected.length - 3})` : ''),
      ];
    });

    autoTable(doc, {
      startY: 25,
      head: [['ID', 'Category', 'Priority', 'Statement', 'Affected Assets']],
      body: threatRows,
      theme: 'striped',
      headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
      bodyStyles: { fontSize: 7 },
      columnStyles: {
        0: { cellWidth: 20 },
        1: { cellWidth: 30 },
        2: { cellWidth: 18 },
        3: { cellWidth: 75 },
        4: { cellWidth: 35 },
      },
      margin: { left: margin, right: margin },
    });

    // ─── Pages 3+: Attack Trees ───
    for (const tree of attackTrees) {
      doc.addPage();
      let yPos = 20;

      // Tree header
      const treeTitle = `${tree.threat_id || 'Unknown'} — ${tree.threat_category || ''}`;
      doc.setFontSize(14);
      doc.setTextColor(...DARK_COLOR);
      doc.text(treeTitle, margin, yPos);
      yPos += 8;

      // Threat statement
      if (tree.threat_statement || tree.threat_description) {
        doc.setFontSize(9);
        doc.setTextColor(80, 80, 80);
        const stmtLines = doc.splitTextToSize(
          tree.threat_statement || tree.threat_description || '',
          contentWidth
        );
        doc.text(stmtLines, margin, yPos);
        yPos += stmtLines.length * 4.5 + 4;
      }

      // Priority
      if (tree.priority) {
        doc.setFontSize(9);
        doc.setTextColor(80, 80, 80);
        doc.text(`Priority: ${tree.priority}`, margin, yPos);
        yPos += 7;
      }

      // Attack Steps
      const steps = Array.isArray(tree.attack_steps) ? tree.attack_steps : [];
      if (steps.length > 0) {
        doc.setFontSize(11);
        doc.setTextColor(...DARK_COLOR);
        doc.text('Attack Steps', margin, yPos);
        yPos += 4;

        const stepRows = steps.map((step) => [
          step.node_id || '',
          step.label || step.description || '',
          step.description || '',
        ]);

        autoTable(doc, {
          startY: yPos,
          head: [['Step ID', 'Label', 'Description']],
          body: stepRows,
          theme: 'striped',
          headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
          bodyStyles: { fontSize: 7 },
          columnStyles: {
            0: { cellWidth: 25 },
            1: { cellWidth: 45 },
            2: { cellWidth: 'auto' },
          },
          margin: { left: margin, right: margin },
        });
      }
    }

    // ─── TTP Mappings ───
    if (allTtpMappings.length > 0) {
      doc.addPage();
      doc.setFontSize(14);
      doc.setTextColor(...DARK_COLOR);
      doc.text('TTP Mappings', margin, 20);

      const ttpRows = allTtpMappings.map((m) => [
        m.threatId || '',
        m.attack_step || '',
        m.technique_id || '',
        m.technique_name || '',
        m.confidence != null ? String(Math.round(m.confidence * 100) / 100) : '',
      ]);

      autoTable(doc, {
        startY: 25,
        head: [['Threat', 'Attack Step', 'TTP ID', 'TTP Name', 'Confidence']],
        body: ttpRows,
        theme: 'striped',
        headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
        bodyStyles: { fontSize: 6.5 },
        columnStyles: {
          0: { cellWidth: 20 },
          1: { cellWidth: 30 },
          2: { cellWidth: 22 },
          3: { cellWidth: 60 },
          4: { cellWidth: 20 },
        },
        margin: { left: margin, right: margin },
      });
    }

    // ─── Mitigations ───
    if (allMitigations.length > 0) {
      doc.addPage();
      doc.setFontSize(14);
      doc.setTextColor(...DARK_COLOR);
      doc.text('Mitigations', margin, 20);

      // Sort by priority (1=critical first)
      const sorted = [...allMitigations].sort((a, b) => {
        const pa = typeof a.priority === 'number' ? a.priority : 99;
        const pb = typeof b.priority === 'number' ? b.priority : 99;
        return pa - pb;
      });

      const mitRows = sorted.map((m) => [
        priorityLabel(m.priority),
        m.name || '',
        REMEDIATION_LABELS[m.remediationType] || m.remediationType || '',
        m.techniqueId || '',
        m.threatId || '',
      ]);

      autoTable(doc, {
        startY: 25,
        head: [['Priority', 'Mitigation', 'Remediation', 'Mapped TTP', 'Threat']],
        body: mitRows,
        theme: 'striped',
        headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
        bodyStyles: { fontSize: 6.5 },
        columnStyles: {
          0: { cellWidth: 18 },
          1: { cellWidth: 75 },
          2: { cellWidth: 25 },
          3: { cellWidth: 22 },
          4: { cellWidth: 20 },
        },
        margin: { left: margin, right: margin },
      });
    }

    // Footer with page numbers
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(150, 150, 150);
      doc.text(
        `Page ${i} of ${pageCount}`,
        pageWidth / 2,
        doc.internal.pageSize.getHeight() - 10,
        { align: 'center' }
      );
      doc.text(
        'Generated by ThreatForest',
        pageWidth - margin,
        doc.internal.pageSize.getHeight() - 10,
        { align: 'right' }
      );
    }

    doc.save(filename || 'threat-model-report.pdf');
  } catch (err) {
    alert(`PDF generation failed: ${(err as Error).message || 'Unknown error'}`);
  }
}

// ─── Threats-only PDF ─────────────────────────────────────────

/**
 * Generate and download a threats-only PDF report.
 * Includes threats overview table and per-threat attack tree sections.
 */
export function exportThreatsPdf(summaryData: ThreatModelSummary | null | undefined, filename?: string): void {
  if (!summaryData || typeof summaryData !== 'object') {
    alert('No threat model data available to export.');
    return;
  }

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) { alert('No threats available to export.'); return; }

  try {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 14;
    const contentWidth = pageWidth - margin * 2;
    const threats = summaryData.threats || [];
    const appName = summaryData.project_info?.application_name || summaryData.application_name || 'Threat Model';

    // Title
    doc.setFontSize(22);
    doc.setTextColor(...DARK_COLOR);
    doc.text('ThreatForest', pageWidth / 2, 35, { align: 'center' });
    doc.setFontSize(16);
    doc.text('Threats Report', pageWidth / 2, 45, { align: 'center' });
    doc.setFontSize(12);
    doc.setTextColor(100, 100, 100);
    doc.text(appName, pageWidth / 2, 57, { align: 'center' });
    doc.text(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }), pageWidth / 2, 65, { align: 'center' });
    doc.setDrawColor(...THEME_COLOR);
    doc.setLineWidth(0.5);
    doc.line(margin, 72, pageWidth - margin, 72);

    // Threats Overview table
    doc.setFontSize(14);
    doc.setTextColor(...DARK_COLOR);
    doc.text('Threats Overview', margin, 82);

    const threatRows = attackTrees.map((tree) => {
      const affected = getAffectedComponents(tree, threats);
      return [
        tree.threat_id || '',
        tree.threat_category || '',
        tree.priority || '',
        tree.threat_statement || tree.threat_description || '',
        affected.slice(0, 3).join(', ') + (affected.length > 3 ? ` (+${affected.length - 3})` : ''),
      ];
    });

    autoTable(doc, {
      startY: 87,
      head: [['ID', 'Category', 'Priority', 'Statement', 'Affected Assets']],
      body: threatRows,
      theme: 'striped',
      headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
      bodyStyles: { fontSize: 7 },
      columnStyles: { 0: { cellWidth: 20 }, 1: { cellWidth: 30 }, 2: { cellWidth: 18 }, 3: { cellWidth: 75 }, 4: { cellWidth: 35 } },
      margin: { left: margin, right: margin },
    });

    // Per-threat attack tree pages
    for (const tree of attackTrees) {
      doc.addPage();
      let yPos = 20;

      doc.setFontSize(14);
      doc.setTextColor(...DARK_COLOR);
      doc.text(`${tree.threat_id || 'Unknown'} — ${tree.threat_category || ''}`, margin, yPos);
      yPos += 8;

      if (tree.threat_statement || tree.threat_description) {
        doc.setFontSize(9);
        doc.setTextColor(80, 80, 80);
        const lines = doc.splitTextToSize(tree.threat_statement || tree.threat_description || '', contentWidth);
        doc.text(lines, margin, yPos);
        yPos += lines.length * 4.5 + 4;
      }

      if (tree.priority) {
        doc.setFontSize(9);
        doc.setTextColor(80, 80, 80);
        doc.text(`Priority: ${tree.priority}`, margin, yPos);
        yPos += 7;
      }

      const steps = Array.isArray(tree.attack_steps) ? tree.attack_steps : [];
      if (steps.length > 0) {
        doc.setFontSize(11);
        doc.setTextColor(...DARK_COLOR);
        doc.text('Attack Steps', margin, yPos);
        yPos += 4;

        autoTable(doc, {
          startY: yPos,
          head: [['Step ID', 'Label', 'Description']],
          body: steps.map((s) => [s.node_id || '', s.label || s.description || '', s.description || '']),
          theme: 'striped',
          headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
          bodyStyles: { fontSize: 7 },
          columnStyles: { 0: { cellWidth: 25 }, 1: { cellWidth: 45 }, 2: { cellWidth: 'auto' } },
          margin: { left: margin, right: margin },
        });
      }
    }

    addPdfFooter(doc, pageWidth, margin);
    doc.save(filename || 'threats-report.pdf');
  } catch (err) {
    alert(`PDF generation failed: ${(err as Error).message || 'Unknown error'}`);
  }
}

/**
 * Generate and download a threats-only PDF without per-step attack-tree
 * detail — overview table only. Mirrors ``exportThreatsPdf`` but omits the
 * per-threat attack-step pages.
 */
export function exportThreatsOnlyPdf(summaryData: ThreatModelSummary | null | undefined, filename?: string): void {
  if (!summaryData || typeof summaryData !== 'object') {
    alert('No threat model data available to export.');
    return;
  }

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) { alert('No threats available to export.'); return; }

  try {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 14;
    const threats = summaryData.threats || [];
    const appName = summaryData.project_info?.application_name || summaryData.application_name || 'Threat Model';

    doc.setFontSize(22);
    doc.setTextColor(...DARK_COLOR);
    doc.text('ThreatForest', pageWidth / 2, 35, { align: 'center' });
    doc.setFontSize(16);
    doc.text('Threats Report', pageWidth / 2, 45, { align: 'center' });
    doc.setFontSize(12);
    doc.setTextColor(100, 100, 100);
    doc.text(appName, pageWidth / 2, 57, { align: 'center' });
    doc.text(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }), pageWidth / 2, 65, { align: 'center' });
    doc.setDrawColor(...THEME_COLOR);
    doc.setLineWidth(0.5);
    doc.line(margin, 72, pageWidth - margin, 72);

    doc.setFontSize(14);
    doc.setTextColor(...DARK_COLOR);
    doc.text('Threats Overview', margin, 82);

    const threatRows = attackTrees.map((tree) => {
      const affected = getAffectedComponents(tree, threats);
      return [
        tree.threat_id || '',
        tree.threat_category || '',
        tree.priority || '',
        tree.threat_statement || tree.threat_description || '',
        affected.slice(0, 3).join(', ') + (affected.length > 3 ? ` (+${affected.length - 3})` : ''),
      ];
    });

    autoTable(doc, {
      startY: 87,
      head: [['ID', 'Category', 'Priority', 'Statement', 'Affected Assets']],
      body: threatRows,
      theme: 'striped',
      headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
      bodyStyles: { fontSize: 7 },
      columnStyles: { 0: { cellWidth: 20 }, 1: { cellWidth: 30 }, 2: { cellWidth: 18 }, 3: { cellWidth: 75 }, 4: { cellWidth: 35 } },
      margin: { left: margin, right: margin },
    });

    addPdfFooter(doc, pageWidth, margin);
    doc.save(filename || 'threats-report.pdf');
  } catch (err) {
    alert(`PDF generation failed: ${(err as Error).message || 'Unknown error'}`);
  }
}

// ─── Mitigations-only PDF ─────────────────────────────────────

/**
 * Generate and download a mitigations-only PDF report.
 */
export function exportMitigationsPdf(summaryData: ThreatModelSummary | null | undefined, filename?: string): void {
  if (!summaryData || typeof summaryData !== 'object') {
    alert('No threat model data available to export.');
    return;
  }

  const attackTrees = Array.isArray(summaryData.attack_trees) ? summaryData.attack_trees : [];
  if (attackTrees.length === 0) { alert('No mitigations available to export.'); return; }

  try {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 14;
    const contentWidth = pageWidth - margin * 2;
    const appName = summaryData.project_info?.application_name || summaryData.application_name || 'Threat Model';

    // Same dedup the UI uses — one row per unique mitigation_text rather than
    // one row per (mitigation × threat) pair, which was inflating counts
    // (UI showed 82, export was producing 130).
    const threats = Array.isArray(summaryData.threats) ? summaryData.threats : [];
    const allMitigations = aggregateAllMitigations(attackTrees, threats);

    if (allMitigations.length === 0) { alert('No mitigations found.'); return; }

    // Sort by priority, then by name for stable ordering across re-exports.
    allMitigations.sort((a, b) => {
      const pa = typeof a.priority === 'number' ? a.priority : 99;
      const pb = typeof b.priority === 'number' ? b.priority : 99;
      if (pa !== pb) return pa - pb;
      return (a.name || '').localeCompare(b.name || '');
    });

    // Title
    doc.setFontSize(22);
    doc.setTextColor(...DARK_COLOR);
    doc.text('ThreatForest', pageWidth / 2, 35, { align: 'center' });
    doc.setFontSize(16);
    doc.text('Mitigations Report', pageWidth / 2, 45, { align: 'center' });
    doc.setFontSize(12);
    doc.setTextColor(100, 100, 100);
    doc.text(appName, pageWidth / 2, 57, { align: 'center' });
    doc.text(new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }), pageWidth / 2, 65, { align: 'center' });
    doc.setDrawColor(...THEME_COLOR);
    doc.setLineWidth(0.5);
    doc.line(margin, 72, pageWidth - margin, 72);

    // ─── Summary ───────────────────────────────────────────────────
    doc.setFontSize(14);
    doc.setTextColor(...DARK_COLOR);
    doc.text('Summary', margin, 82);

    const criticalCount = allMitigations.filter((m) => m.priority === 1).length;
    const highCount = allMitigations.filter((m) => m.priority === 2).length;
    const threatsCovered = new Set<string>();
    for (const m of allMitigations) {
      for (const t of m.threats || []) if (t.id) threatsCovered.add(t.id);
    }
    const statusCounts = allMitigations.reduce<Record<string, number>>((acc, m) => {
      const key = m.overrideStatus || 'open';
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});

    autoTable(doc, {
      startY: 87,
      head: [['Metric', 'Value']],
      body: [
        ['Total mitigations', String(allMitigations.length)],
        ['Critical priority', String(criticalCount)],
        ['High priority', String(highCount)],
        ['Threats covered', String(threatsCovered.size)],
        ['Already implemented', String(statusCounts.already_implemented || 0)],
        ['In progress', String(statusCounts.in_progress || 0)],
        ['Accepted risk', String(statusCounts.accepted_risk || 0)],
        ['Not relevant', String(statusCounts.not_relevant || 0)],
        ["Won't do", String(statusCounts.wont_do || 0)],
        ['Open (no status)', String(statusCounts.open || 0)],
      ],
      theme: 'grid',
      headStyles: { fillColor: THEME_COLOR, fontSize: 10 },
      bodyStyles: { fontSize: 10 },
      columnStyles: { 0: { cellWidth: 60, fontStyle: 'bold' }, 1: { cellWidth: 40 } },
      margin: { left: margin, right: margin },
      tableWidth: 100,
    });

    // ─── Overview table ────────────────────────────────────────────
    // Compact one-line-per-mitigation index. Full guidance lives below in
    // the per-mitigation detail section so we don't truncate it here.
    doc.addPage();
    doc.setFontSize(14);
    doc.setTextColor(...DARK_COLOR);
    doc.text('Mitigations overview', margin, 20);

    autoTable(doc, {
      startY: 25,
      head: [['#', 'Priority', 'Status', 'Mitigation', 'Type', 'Mapped TTP', 'Threats']],
      body: allMitigations.map((m, i) => {
        const info = statusInfo(m.overrideStatus);
        return [
          String(i + 1),
          priorityLabel(m.priority),
          info ? info.label : 'Open',
          m.name || '',
          REMEDIATION_LABELS[m.remediationType] || m.remediationType || '',
          m.techniqueId || '',
          (m.threats || []).map((t) => t.id).filter(Boolean).join(', '),
        ];
      }),
      theme: 'striped',
      headStyles: { fillColor: THEME_COLOR, fontSize: 8 },
      bodyStyles: { fontSize: 7, valign: 'top' },
      columnStyles: {
        0: { cellWidth: 8 },
        1: { cellWidth: 16 },
        2: { cellWidth: 26 },
        3: { cellWidth: 60 },
        4: { cellWidth: 22 },
        5: { cellWidth: 22 },
        6: { cellWidth: 28 },
      },
      margin: { left: margin, right: margin },
    });

    // ─── Per-mitigation detail with full implementation guidance ──
    doc.addPage();
    let yPos = 20;
    doc.setFontSize(14);
    doc.setTextColor(...DARK_COLOR);
    doc.text('Mitigation detail', margin, yPos);
    yPos += 9;

    /**
     * Reserve `needed` units of vertical space; emit a page break first if
     * we'd otherwise render below the bottom margin.
     */
    function ensureSpace(needed: number): void {
      if (yPos + needed > pageHeight - 20) {
        doc.addPage();
        yPos = 20;
      }
    }

    for (let i = 0; i < allMitigations.length; i++) {
      const m = allMitigations[i];
      if (!m) continue;
      const info = statusInfo(m.overrideStatus);

      ensureSpace(28);

      // Heading: "1. <name>"
      doc.setFontSize(11);
      doc.setTextColor(...DARK_COLOR);
      const headingLines = doc.splitTextToSize(`${i + 1}. ${m.name || ''}`, contentWidth);
      doc.text(headingLines, margin, yPos);
      yPos += headingLines.length * 5 + 1;

      // Meta line: priority · type · technique · threats
      doc.setFontSize(8);
      doc.setTextColor(100, 100, 100);
      const metaParts = [
        `Priority: ${priorityLabel(m.priority)}`,
        `Type: ${REMEDIATION_LABELS[m.remediationType] || m.remediationType || '—'}`,
        `Mapped TTP: ${m.techniqueId || '—'}`,
        `Threats: ${(m.threats || []).map((t) => t.id).filter(Boolean).join(', ') || '—'}`,
      ];
      const metaLines = doc.splitTextToSize(metaParts.join('   ·   '), contentWidth);
      ensureSpace(metaLines.length * 4 + 3);
      doc.text(metaLines, margin, yPos);
      yPos += metaLines.length * 4 + 3;

      // Status row (only when one is set — Open is implicit otherwise).
      if (info) {
        ensureSpace(8);
        doc.setFontSize(9);
        doc.setTextColor(...DARK_COLOR);
        doc.text(`Status: ${info.label}`, margin, yPos);
        yPos += 5;
        if (m.overrideComment) {
          doc.setFontSize(8);
          doc.setTextColor(80, 80, 80);
          const commentLines = doc.splitTextToSize(`Comment: ${m.overrideComment}`, contentWidth);
          ensureSpace(commentLines.length * 4 + 2);
          doc.text(commentLines, margin, yPos);
          yPos += commentLines.length * 4 + 2;
        }
      }

      // Implementation guidance — full text, wrapped, no truncation.
      if (m.description) {
        ensureSpace(8);
        doc.setFontSize(9);
        doc.setTextColor(...DARK_COLOR);
        doc.text('Implementation guidance', margin, yPos);
        yPos += 4;
        doc.setFontSize(8);
        doc.setTextColor(60, 60, 60);
        const guidanceLines = doc.splitTextToSize(m.description, contentWidth);
        // Long lists may not fit on this page — break per-line so we never
        // overrun the bottom margin.
        const lineHeight = 4;
        for (const line of guidanceLines) {
          ensureSpace(lineHeight);
          doc.text(line, margin, yPos);
          yPos += lineHeight;
        }
      }

      yPos += 4; // gap between mitigations

      // Light divider between entries (skip after the last).
      if (i < allMitigations.length - 1) {
        ensureSpace(2);
        doc.setDrawColor(220, 220, 220);
        doc.setLineWidth(0.2);
        doc.line(margin, yPos, pageWidth - margin, yPos);
        yPos += 4;
      }
    }

    addPdfFooter(doc, pageWidth, margin);
    doc.save(filename || 'mitigations-report.pdf');
  } catch (err) {
    alert(`PDF generation failed: ${(err as Error).message || 'Unknown error'}`);
  }
}

// ─── Shared PDF footer helper ─────────────────────────────────

function addPdfFooter(doc: jsPDF, pageWidth: number, margin: number): void {
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(`Page ${i} of ${pageCount}`, pageWidth / 2, doc.internal.pageSize.getHeight() - 10, { align: 'center' });
    doc.text('Generated by ThreatForest', pageWidth - margin, doc.internal.pageSize.getHeight() - 10, { align: 'right' });
  }
}
