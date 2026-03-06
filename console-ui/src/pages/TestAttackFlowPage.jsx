import { useState, useEffect } from 'react';
import Box from '@cloudscape-design/components/box';
import Header from '@cloudscape-design/components/header';
import Spinner from '@cloudscape-design/components/spinner';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Select from '@cloudscape-design/components/select';
import FormField from '@cloudscape-design/components/form-field';
import CloudscapeShell from '../components/CloudscapeShell';
import AttackFlowViewer from '../components/AttackFlowViewer';

/**
 * Test page that loads the vehicle platform sample data directly
 * from /test-data.json (copied into public/) to visually test
 * the Attack Flow Builder-styled UI without requiring the backend.
 */
export default function TestAttackFlowPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedOption, setSelectedOption] = useState(null);

  useEffect(() => {
    fetch('/test-data.json')
      .then(r => r.json())
      .then(json => {
        setData(json);
        if (json.attack_trees?.length > 0) {
          const t = json.attack_trees[0];
          setSelectedOption({
            label: `${t.threat_id} — ${t.threat_category} (${t.priority})`,
            value: '0',
          });
        }
      })
      .finally(() => setLoading(false));
  }, []);

  const attackTrees = data?.attack_trees || [];
  const selectedIdx = selectedOption ? parseInt(selectedOption.value, 10) : 0;
  const selectedTree = attackTrees[selectedIdx] || null;

  const threatOptions = attackTrees.map((t, i) => ({
    label: `${t.threat_id || `Threat ${i + 1}`} — ${t.threat_category || 'Unknown'} (${t.priority || '—'})`,
    value: String(i),
  }));

  return (
    <CloudscapeShell activePage="/" breadcrumbs={[{ text: 'Home', href: '/' }, { text: 'Attack Flow Test', href: '/test-attack-flow' }]}>
      {loading ? (
        <Box textAlign="center" padding="l"><Spinner size="large" /></Box>
      ) : (
        <SpaceBetween size="m">
          <Header variant="h1">Attack Flow Viewer — Test Page</Header>
          <Box variant="p" color="text-body-secondary">
            Loaded {attackTrees.length} attack trees from vehicle-platform sample data.
          </Box>
          {threatOptions.length > 0 && (
            <div style={{ maxWidth: 500 }}>
              <FormField label="Select threat">
                <Select
                  selectedOption={selectedOption}
                  onChange={({ detail }) => setSelectedOption(detail.selectedOption)}
                  options={threatOptions}
                  placeholder="Choose a threat..."
                />
              </FormField>
            </div>
          )}
          {selectedTree && (
            <div style={{ border: '1px solid #d5dbdb', borderRadius: 8, overflow: 'hidden' }}>
              <AttackFlowViewer attackTree={selectedTree} />
            </div>
          )}
        </SpaceBetween>
      )}
    </CloudscapeShell>
  );
}