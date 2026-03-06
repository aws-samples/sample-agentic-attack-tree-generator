/**
 * Export service for attack tree data.
 * Provides CSV and PDF export functionality.
 */
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

/**
 * Escape a CSV field value per RFC 4180.
 * If the value contains a comma, double-quote, or newline, wrap it in double-quotes
 * and escape any internal double-quotes by doubling them.
 * @param {string} value - The field value
 * @returns {string} The escaped field value
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
 * Build a lookup from attack_step identifiers to display labels.
 * @param {Array} attackSteps - The attack_steps array from the attack tree
 * @returns {Map<string, string>}
 */
function buildStepLabelMap(attackSteps) {
  const labelMap = new Map();
  if (!Array.isArray(attackSteps)) return labelMap;
  for (const step of attackSteps) {
    const label = step.label || step.description || step.node_id || '';
    if (step.node_id) labelMap.set(step.node_id, label);
    if (step.description) labelMap.set(step.description, label);
    if (step.label) labelMap.set(step.label, label);
  }
  return labelMap;
}

/**
 * Collect MITRE technique mappings for a given attack step.
 * Matches by node_id, label, or description.
 * @param {Object} step - An attack step object
 * @param {Array} ttcMappings - The ttc_mappings array from the attack tree
 * @returns {Array<{technique_id: string, technique_name: string}>}
 */
function getTtcMappingsForStep(step, ttcMappings) {
  if (!Array.isArray(ttcMappings)) return [];
  const identifiers = [step.node_id, step.label, step.description].filter(Boolean);
  return ttcMappings.filter(m => identifiers.includes(m.attack_step));
}

/**
 * Collect mitigations for a given attack step from all sources.
 * Sources: step.mitigations, ttc_mappings[].mitigations, tree-level mitigations.
 * @param {Object} step - An attack step object
 * @param {Array} ttcMappingsForStep - Filtered TTC mappings for this step
 * @param {Array} treeMitigations - Tree-level mitigations array
 * @returns {Array<string>} Deduplicated mitigation names
 */
function getMitigationNamesForStep(step, ttcMappingsForStep, treeMitigations) {
  const names = new Set();

  // From step.mitigations
  if (Array.isArray(step.mitigations)) {
    for (const mit of step.mitigations) {
      const name = mit.name || mit.mitigation || '';
      if (name) names.add(name);
    }
  }

  // From ttc_mappings[].mitigations
  for (const mapping of ttcMappingsForStep) {
    if (Array.isArray(mapping.mitigations)) {
      for (const mit of mapping.mitigations) {
        const name = mit.name || mit.mitigation || '';
        if (name) names.add(name);
      }
    }
  }

  // From tree-level mitigations
  if (Array.isArray(treeMitigations)) {
    const identifiers = [step.node_id, step.label, step.description].filter(Boolean);
    for (const mit of treeMitigations) {
      if (identifiers.includes(mit.attack_step)) {
        const name = mit.name || mit.mitigation || '';
        if (name) names.add(name);
      }
    }
  }

  return [...names];
}

/**
 * Generate CSV string from attack tree data.
 * Produces one row per attack step with columns:
 *   Step Name, Step Description, MITRE Technique IDs, MITRE Technique Names, Mitigation Names
 *
 * Multi-value fields (techniques, mitigations) are separated by semicolons.
 * Special characters are escaped per RFC 4180.
 *
 * @param {Object} attackTree - The attack tree object
 * @returns {string} CSV content
 */
export function generateCsvContent(attackTree) {
  if (!attackTree || typeof attackTree !== 'object') {
    return '';
  }

  const attackSteps = Array.isArray(attackTree.attack_steps) ? attackTree.attack_steps : [];
  const ttcMappings = Array.isArray(attackTree.ttc_mappings) ? attackTree.ttc_mappings : [];
  const treeMitigations = Array.isArray(attackTree.mitigations) ? attackTree.mitigations : [];

  if (attackSteps.length === 0) {
    return '';
  }

  const header = ['Step Name', 'Step Description', 'MITRE Technique IDs', 'MITRE Technique Names', 'Mitigation Names'];
  const rows = [header.map(escapeCsvField).join(',')];

  for (const step of attackSteps) {
    const stepName = step.label || step.description || step.node_id || '';
    const stepDescription = step.description || '';
    const mappings = getTtcMappingsForStep(step, ttcMappings);
    const techniqueIds = mappings.map(m => m.technique_id || '').filter(Boolean).join(';');
    const techniqueNames = mappings.map(m => m.technique_name || '').filter(Boolean).join(';');
    const mitigationNames = getMitigationNamesForStep(step, mappings, treeMitigations).join(';');

    const row = [
      escapeCsvField(stepName),
      escapeCsvField(stepDescription),
      escapeCsvField(techniqueIds),
      escapeCsvField(techniqueNames),
      escapeCsvField(mitigationNames),
    ];
    rows.push(row.join(','));
  }

  return rows.join('\n');
}

/**
 * Trigger browser download of a CSV file.
 * @param {Object} attackTree - The attack tree object
 * @param {string} filename - Download filename (should end in .csv)
 */
export function exportCsv(attackTree, filename) {
  const csvContent = generateCsvContent(attackTree);
  if (!csvContent) {
    alert('No attack tree data available to export.');
    return;
  }

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename || 'attack-tree-export.csv';
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Generate and download a PDF document from attack tree data.
 *
 * Page 1: Title and summary data (total threats, high severity, attack trees count, TTP mappings).
 * Page 2+: Threat details with attack steps table, MITRE mappings, and mitigations.
 *
 * @param {Object} attackTree - The attack tree object
 * @param {Object} summaryData - Dashboard summary data with extraction_summary, mapping_summary, attack_trees
 * @param {string} filename - Download filename (should end in .pdf)
 */
export function exportPdf(attackTree, summaryData, filename) {
  if (!attackTree || typeof attackTree !== 'object') {
    alert('No attack tree data available to export.');
    return;
  }

  const attackSteps = Array.isArray(attackTree.attack_steps) ? attackTree.attack_steps : [];
  if (attackSteps.length === 0) {
    alert('No attack steps available to export.');
    return;
  }

  const ttcMappings = Array.isArray(attackTree.ttc_mappings) ? attackTree.ttc_mappings : [];
  const treeMitigations = Array.isArray(attackTree.mitigations) ? attackTree.mitigations : [];

  try {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();

    // --- Page 1: Title and Summary ---
    doc.setFontSize(20);
    doc.text('ThreatForest Attack Tree Report', pageWidth / 2, 30, { align: 'center' });

    doc.setFontSize(12);
    doc.text('Summary', 14, 50);

    const ext = summaryData?.extraction_summary || {};
    const map = summaryData?.mapping_summary || {};
    const treeCount = Array.isArray(summaryData?.attack_trees) ? summaryData.attack_trees.length : 0;

    const summaryRows = [
      ['Total Threats', String(ext.total_threats ?? 0)],
      ['High Severity', String(ext.high_severity_count ?? 0)],
      ['Attack Trees', String(treeCount)],
      ['TTP Mappings', String(map.total_mappings ?? 0)],
    ];

    autoTable(doc, {
      startY: 55,
      head: [['Metric', 'Value']],
      body: summaryRows,
      theme: 'grid',
      headStyles: { fillColor: [41, 128, 185] },
      margin: { left: 14, right: 14 },
    });

    // --- Page 2+: Threat Details ---
    doc.addPage();
    let yPos = 20;

    // Threat header
    doc.setFontSize(16);
    doc.text('Threat Details', 14, yPos);
    yPos += 10;

    doc.setFontSize(11);
    if (attackTree.threat_statement) {
      const statementLines = doc.splitTextToSize(
        `Threat: ${attackTree.threat_statement}`,
        pageWidth - 28
      );
      doc.text(statementLines, 14, yPos);
      yPos += statementLines.length * 6 + 4;
    }
    if (attackTree.priority) {
      doc.text(`Priority: ${attackTree.priority}`, 14, yPos);
      yPos += 8;
    }

    // Attack Steps Table
    doc.setFontSize(13);
    doc.text('Attack Steps', 14, yPos);
    yPos += 4;

    const stepTableBody = attackSteps.map(step => {
      const stepName = step.label || step.description || step.node_id || '';
      const stepDesc = step.description || '';
      const mappings = getTtcMappingsForStep(step, ttcMappings);
      const techniqueIds = mappings.map(m => m.technique_id || '').filter(Boolean).join('; ');
      const techniqueNames = mappings.map(m => m.technique_name || '').filter(Boolean).join('; ');
      const mitigationNames = getMitigationNamesForStep(step, mappings, treeMitigations).join('; ');
      return [stepName, stepDesc, techniqueIds, techniqueNames, mitigationNames];
    });

    autoTable(doc, {
      startY: yPos,
      head: [['Step Name', 'Description', 'MITRE IDs', 'MITRE Names', 'Mitigations']],
      body: stepTableBody,
      theme: 'striped',
      headStyles: { fillColor: [41, 128, 185], fontSize: 8 },
      bodyStyles: { fontSize: 7 },
      columnStyles: {
        0: { cellWidth: 30 },
        1: { cellWidth: 45 },
        2: { cellWidth: 25 },
        3: { cellWidth: 40 },
        4: { cellWidth: 40 },
      },
      margin: { left: 14, right: 14 },
    });

    doc.save(filename || 'attack-tree-report.pdf');
  } catch (err) {
    alert(`PDF generation failed: ${err.message || 'Unknown error'}`);
  }
}
