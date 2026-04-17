import React, { useState } from 'react';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import Alert from '@cloudscape-design/components/alert';
import { exportCsv, exportPdf, exportThreatsCsv, exportThreatsPdf, exportMitigationsCsv, exportMitigationsPdf } from '../utils/export-service';

const EXPORT_ITEMS = [
  {
    id: 'export-all',
    text: 'Export All',
    items: [
      { id: 'all-pdf', text: 'PDF' },
      { id: 'all-csv', text: 'CSV' },
    ],
  },
  {
    id: 'export-threats',
    text: 'Export Threats',
    items: [
      { id: 'threats-pdf', text: 'PDF' },
      { id: 'threats-csv', text: 'CSV' },
    ],
  },
  {
    id: 'export-mitigations',
    text: 'Export Mitigations',
    items: [
      { id: 'mitigations-pdf', text: 'PDF' },
      { id: 'mitigations-csv', text: 'CSV' },
    ],
  },
];

function buildFilename(appId, versionId, scope, extension) {
  const parts = ['threat-model'];
  if (appId) parts.push(appId);
  if (versionId) parts.push(versionId);
  if (scope) parts.push(scope);
  return `${parts.join('-')}.${extension}`;
}

export default function ExportButton({ summaryData, appId, versionId }) {
  const [error, setError] = useState(null);

  function handleClick({ detail }) {
    setError(null);

    const trees = summaryData?.attack_trees;
    if (!summaryData || !Array.isArray(trees) || trees.length === 0) {
      setError('No threat model data available to export.');
      return;
    }

    switch (detail.id) {
      case 'all-pdf':
        exportPdf(summaryData, buildFilename(appId, versionId, null, 'pdf'));
        break;
      case 'all-csv':
        exportCsv(summaryData, buildFilename(appId, versionId, null, 'csv'));
        break;
      case 'threats-pdf':
        exportThreatsPdf(summaryData, buildFilename(appId, versionId, 'threats', 'pdf'));
        break;
      case 'threats-csv':
        exportThreatsCsv(summaryData, buildFilename(appId, versionId, 'threats', 'csv'));
        break;
      case 'mitigations-pdf':
        exportMitigationsPdf(summaryData, buildFilename(appId, versionId, 'mitigations', 'pdf'));
        break;
      case 'mitigations-csv':
        exportMitigationsCsv(summaryData, buildFilename(appId, versionId, 'mitigations', 'csv'));
        break;
      default:
        break;
    }
  }

  return (
    <>
      {error && (
        <Alert type="error" dismissible onDismiss={() => setError(null)} data-testid="export-error-alert">
          {error}
        </Alert>
      )}
      <ButtonDropdown
        items={EXPORT_ITEMS}
        onItemClick={handleClick}
        expandableGroups
        data-testid="export-button"
      >
        Export
      </ButtonDropdown>
    </>
  );
}
