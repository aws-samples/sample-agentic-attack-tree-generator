/**
 * Export service for threat model data.
 * Provides comprehensive CSV and PDF export covering all threats, attack trees,
 * TTP mappings, and mitigations — mirroring the threat_model_report.md structure.
 */
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { aggregateMitigations } from './mitigation-aggregator';

/**
 * Escape a CSV field value per RFC 4180.
 */
function escapeCsvField(value) {
  if (value == null) return '';
  const str = String(value);
  if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

/**
 * Get affected components for a threat by matching threat_id against the threats array.
 */
function getAffectedComponents(tree, threats) {
  const threatsList = Array.isArray(threats) ? threats : [];
  const matchId = (tree.threat_id || '').replace(/ \[AttackTree.*\]/, '');
  const match = threatsList.find(t => (t.id || t.threat_id) === matchId);
  return match?.affected_components || match?.impactedAssets || [];
}

/**
 * Remediation type display labels.
 */
const REMEDIATION_LABELS = {
  quick_win: 'Quick Win',
  short_term: 'Short Term',
  medium_term: 'Medium Term',
  long_term: 'Long Term',
  monitoring: 'Monitoring & Detection',
};

/**
 * Priority display labels for numeric priorities.
 */
function priorityLabel(p) {
  if (typeof p === 'number') return ['', 'Critical', 'High', 'Medium', 'Low'][p] || `P${p}`;
  return p || '';
}

// ─── CSV Export ───────────────────────────────────────────────

/**
 * Generate comprehensive CSV content from all threat model data.
 * Produces a mitigations-focused CSV with one row per mitigation across all threats.
 *
 * @param {Object} summaryData - Full threat model data with attack_trees, threats, etc.
 * @returns {string} CSV content
 */
export function generateCsvContent(summaryData) {
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
    'Technique',
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
 * @param {Object} summaryData - Full threat model data
 * @param {string} filename - Download filename
 */
export function exportCsv(summaryData, filename) {
  const csvContent = generateCsvContent(summaryData);
  if (!csvContent) {
    alert('No threat model data available to export.');
    return;
  }

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename || 'threat-model-report.csv';
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
const THEME_COLOR = [41, 128, 185];
const DARK_COLOR = [44, 62, 80];

/**
 * Generate and download a comprehensive PDF threat model report.
 *
 * Structure mirrors threat_model_report.md:
 *   1. Title + Executive Summary
 *   2. Threats Overview table
 *   3. Attack Trees (per-tree sections with steps)
 *   4. TTP Mappings table (all trees)
 *   5. Mitigations table (all trees)
 *
 * @param {Object} summaryData - Full threat model data
 * @param {string} filename - Download filename
 */
export function exportPdf(summaryData, filename) {
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
    const allMitigations = [];
    const allTtpMappings = [];
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
          tree.threat_statement || tree.threat_description,
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
        head: [['Threat', 'Attack Step', 'Technique ID', 'Technique Name', 'Confidence']],
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
        head: [['Priority', 'Mitigation', 'Remediation', 'Technique', 'Threat']],
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
    const pageCount = doc.internal.getNumberOfPages();
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
    alert(`PDF generation failed: ${err.message || 'Unknown error'}`);
  }
}
