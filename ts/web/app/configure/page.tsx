'use client';

/**
 * Route "/configure" — TS/Next port of console-ui's pages/ConfigurePage.jsx.
 *
 * Hosted model selection.
 *
 * The hosted deployment owns its AWS identity and region. Users therefore
 * choose only from the Bedrock catalogue returned by the control plane; local
 * AWS profiles, regions, provider credentials, and arbitrary model ids are not
 * meaningful in this UI.
 */

import { useState, useEffect } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import Button from '@cloudscape-design/components/button';
import Flashbar, { type FlashbarProps } from '@cloudscape-design/components/flashbar';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Container from '@cloudscape-design/components/container';
import Box from '@cloudscape-design/components/box';
import Spinner from '@cloudscape-design/components/spinner';
import AppShell from '@/components/AppShell';
import {
  getConfig,
  getBedrockModels,
  testConnection,
  saveConfig,
} from '@/api/client';
import type { BedrockModel } from '@threatforest/types';

function modelDescription(model: BedrockModel): string {
  const details = [model.provider];
  details.push(model.is_inference_profile ? 'cross-region profile' : 'on-demand');
  if (model.lifecycle === 'LEGACY') details.push('legacy');
  return details.join(' · ');
}

export default function ConfigurePage() {
  const [loading, setLoading] = useState(true);
  const [awsRegion, setAwsRegion] = useState('');
  const [modelId, setModelId] = useState('');
  const [modelIdOption, setModelIdOption] = useState<SelectProps.Option | null>(null);
  const [bedrockModels, setBedrockModels] = useState<BedrockModel[]>([]);
  const [bedrockSource, setBedrockSource] = useState<'live' | 'fallback' | null>(null);
  const [bedrockWarning, setBedrockWarning] = useState<string | null>(null);
  const [loadingModels, setLoadingModels] = useState(false);
  const [flashItems, setFlashItems] = useState<FlashbarProps.MessageDefinition[]>([]);
  const [testingConnection, setTestingConnection] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      try {
        const [configData, modelsData] = await Promise.all([
          getConfig(),
          getBedrockModels(),
        ]);

        if (cancelled) return;

        setAwsRegion(modelsData.region || configData.aws_region || '');
        setModelId(configData.model_id || '');
        setBedrockModels(modelsData.models);
        setBedrockSource(modelsData.source);
        setBedrockWarning(modelsData.warning);

        const selected = modelsData.models.find((model) => model.id === configData.model_id);
        if (selected) {
          setModelIdOption({
            label: selected.label,
            value: selected.id,
            description: modelDescription(selected),
          });
        }
      } catch (err) {
        if (!cancelled) {
          setFlashItems([
            {
              type: 'error',
              dismissible: true,
              content: (err as Error).message || 'Failed to load configuration.',
              id: 'load-error',
              onDismiss: () =>
                setFlashItems((items) => items.filter((i) => i.id !== 'load-error')),
            },
          ]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadData();
    return () => {
      cancelled = true;
    };
  }, []);

  const buildTestConfig = () => ({
    provider: 'AWS Bedrock',
    model_id: modelId,
    aws_region: awsRegion || null,
    aws_profile: null,
    api_key: null,
  });

  const buildSaveConfig = () => ({
    provider: 'AWS Bedrock',
    model_id: modelId,
    aws_region: awsRegion || null,
    aws_profile: null,
    api_key: null,
  });

  const addFlash = (type: FlashbarProps.Type, content: string, id: string) => {
    setFlashItems((prev) => [
      ...prev.filter((i) => i.id !== id),
      {
        type,
        dismissible: true,
        content,
        id,
        onDismiss: () => setFlashItems((items) => items.filter((i) => i.id !== id)),
      },
    ]);
  };

  const handleTestConnection = async () => {
    setTestingConnection(true);
    try {
      const result = await testConnection(buildTestConfig());
      addFlash(
        result.success ? 'success' : 'error',
        result.message || (result.success ? 'Connection successful.' : 'Connection failed.'),
        'test-result',
      );
      if (result.success) {
        try {
          const signature = JSON.stringify({
            provider: 'AWS Bedrock',
            model_id: modelId,
            aws_region: awsRegion || '',
            aws_profile: '',
          });
          window.localStorage.setItem('threatforest.configVerified', signature);
        } catch {
          // localStorage unavailable — non-fatal
        }
      }
    } catch (err) {
      addFlash('error', (err as Error).message || 'Connection test failed.', 'test-result');
    } finally {
      setTestingConnection(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const result = await saveConfig(buildSaveConfig());
      addFlash(
        result.success ? 'success' : 'error',
        result.message || (result.success ? 'Configuration saved.' : 'Save failed.'),
        'save-result',
      );
    } catch (err) {
      addFlash('error', (err as Error).message || 'Failed to save configuration.', 'save-result');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <AppShell
        activePage="/configure"
        breadcrumbs={[
          { text: 'Home', href: '/' },
          { text: 'Configure', href: '/configure' },
        ]}
      >
        <Box textAlign="center" padding="xxl">
          <Spinner size="large" />
        </Box>
      </AppShell>
    );
  }

  const bedrockOptions: SelectProps.Options = (() => {
    const recommended = bedrockModels.filter((model) => model.recommended);
    const other = bedrockModels.filter((model) => !model.recommended);
    const groups: SelectProps.OptionGroup[] = [];
    if (recommended.length > 0) {
      groups.push({
        label: 'Recommended for ThreatForest',
        options: recommended.map((model) => ({
          label: model.label,
          value: model.id,
          description: modelDescription(model),
        })),
      });
    }
    if (other.length > 0) {
      groups.push({
        label: 'Other Bedrock models',
        options: other.map((model) => ({
          label: model.label,
          value: model.id,
          description: modelDescription(model),
        })),
      });
    }
    return groups;
  })();

  // Warn when the chosen id is on its way out — the whole point of reading
  // lifecycle from the API instead of hardcoding a list.
  const selectedBedrockModel = bedrockModels.find((m) => m.id === modelId) ?? null;
  const bedrockFieldStatus = ((): { type: 'error' | 'warning' | 'info'; text: string } | null => {
    if (loadingModels) return { type: 'info', text: 'Loading models from Bedrock…' };
    if (bedrockWarning) return { type: 'warning', text: bedrockWarning };
    if (selectedBedrockModel?.lifecycle === 'LEGACY') {
      const when = selectedBedrockModel.end_of_life
        ? ` It reaches end of life on ${selectedBedrockModel.end_of_life.slice(0, 10)}.`
        : '';
      return {
        type: 'warning',
        text: `${selectedBedrockModel.id} is marked LEGACY by Bedrock.${when}`,
      };
    }
    if (bedrockSource === 'live') {
      return {
        type: 'info',
        text: `${bedrockModels.length} models available from the hosted Bedrock catalogue in ${awsRegion || 'the deployment region'}.`,
      };
    }
    return null;
  })();

  return (
    <AppShell
      activePage="/configure"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Configure', href: '/configure' },
      ]}
    >
      <ContentLayout
        header={
          <Header
            variant="h1"
            description="Choose the Bedrock model used for threat modeling and manage observability integrations."
          >
            Configure
          </Header>
        }
      >
        <SpaceBetween size="l">
          <Flashbar items={flashItems} />

          {/* Model & AWS Settings */}
          <Form
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  onClick={handleTestConnection}
                  loading={testingConnection}
                  disabled={
                    !modelId
                  }
                  iconName="status-positive"
                >
                  Test Connection
                </Button>
                <Button
                  variant="primary"
                  onClick={handleSave}
                  loading={saving}
                  disabled={
                    !modelId
                  }
                >
                  Save Configuration
                </Button>
              </SpaceBetween>
            }
          >
            <SpaceBetween size="l">
              <Container header={<Header variant="h2">Model settings</Header>}>
                <SpaceBetween size="l">
                  <FormField
                      label="Bedrock model"
                      description="Choose from the models exposed by the hosted Bedrock deployment, including models served by Bedrock's Mantle infrastructure."
                      {...(bedrockFieldStatus?.type === 'warning'
                        ? { warningText: bedrockFieldStatus.text }
                        : {})}
                      {...(bedrockFieldStatus?.type === 'info'
                        ? { constraintText: bedrockFieldStatus.text }
                        : {})}
                      secondaryControl={
                          <Button
                            iconName="refresh"
                            loading={loadingModels}
                            ariaLabel="Refresh the Bedrock model list"
                            onClick={() => {
                              setLoadingModels(true);
                              getBedrockModels({ refresh: true })
                                .then((data) => {
                                  setBedrockModels(data.models);
                                  setBedrockSource(data.source);
                                  setBedrockWarning(data.warning);
                                  setAwsRegion(data.region);
                                })
                                .catch((err: Error) => setBedrockWarning(err.message))
                                .finally(() => setLoadingModels(false));
                            }}
                          />
                      }
                    >
                        <Select
                          selectedOption={modelIdOption}
                          onChange={({ detail }) => {
                            setModelIdOption(detail.selectedOption);
                            setModelId(detail.selectedOption.value ?? '');
                          }}
                          options={bedrockOptions}
                          placeholder="Choose a Bedrock model"
                          loadingText="Loading models…"
                          statusType={loadingModels ? 'loading' : 'finished'}
                          empty="No matching Bedrock models"
                          filteringType="auto"
                        />
                    </FormField>
                </SpaceBetween>
              </Container>
            </SpaceBetween>
          </Form>

        </SpaceBetween>
      </ContentLayout>
    </AppShell>
  );
}
