import React, { useState } from 'react';
import ButtonDropdown from '@cloudscape-design/components/button-dropdown';
import Alert from '@cloudscape-design/components/alert';
import { exportCsv, exportPdf } from '../utils/export-service';

const EXPORT_ITEMS = [
  { id: 'export-pdf', text: 'Export PDF' },
  { id: 'export-csv', text: 'Export CSV' },
];

function buildFilename(appId, versionId, extension) {
  const parts = ['attack-tree'];
  if (appId) parts.push(appId);
  if (versionId) parts.push(versionId);
  return `${parts.join('-')}.${extension}`;
}

export default function ExportButton({ attackTree, summaryData, appId, versionId }) {
  const [error, setError] = useState(null);

  function handleClick({ detail }) {
    setError(null);

    if (!attackTree || typeof attackTree !== 'object' || !Array.isArray(attackTree.attack_steps) || attackTree.attack_steps.length === 0) {
      setError('No attack tree data available to export.');
      return;
    }

    if (detail.id === 'export-csv') {
      exportCsv(attackTree, buildFilename(appId, versionId, 'csv'));
    } else if (detail.id === 'export-pdf') {
      exportPdf(attackTree, summaryData, buildFilename(appId, versionId, 'pdf'));
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
        data-testid="export-button"
      >
        Export
      </ButtonDropdown>
    </>
  );
}
