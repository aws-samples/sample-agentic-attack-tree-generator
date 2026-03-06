import React, { useState, useEffect } from 'react';
import CloudscapeShell from '../components/CloudscapeShell';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Select from '@cloudscape-design/components/select';
import Button from '@cloudscape-design/components/button';
import Flashbar from '@cloudscape-design/components/flashbar';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Container from '@cloudscape-design/components/container';
import Box from '@cloudscape-design/components/box';
import Spinner from '@cloudscape-design/components/spinner';
import { getConfig, getProviders, testConnection, saveConfig } from '../api-client';

// Model options per provider — mirrors model_configs.py from the CLI
const PROVIDER_MODELS = {
  'AWS Bedrock': [
    { label: 'Amazon Nova 2 Lite', value: 'global.amazon.nova-2-lite-v1:0' },
    { label: 'Claude Haiku 4.5', value: 'global.anthropic.claude-haiku-4-5-20251001-v1:0' },
    { label: 'Claude Sonnet 4.5', value: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0' },
    { label: 'Claude Sonnet 4.6', value: 'global.anthropic.claude-sonnet-4-6' },
    { label: 'Claude Opus 4.5', value: 'global.anthropic.claude-opus-4-5-20251101-v1:0' },
    { label: 'Claude Opus 4.6', value: 'global.anthropic.claude-opus-4-6-v1' },
  ],
  'Anthropic': [
    { label: 'Claude 3 Sonnet', value: 'claude-3-sonnet-20240229' },
    { label: 'Claude 3 Opus', value: 'claude-3-opus-20240229' },
    { label: 'Claude 3 Haiku', value: 'claude-3-haiku-20240307' },
    { label: 'Claude Sonnet 4', value: 'claude-sonnet-4-20250514' },
  ],
  'OpenAI': [
    { label: 'GPT-4o', value: 'gpt-4o' },
    { label: 'GPT-4 Turbo', value: 'gpt-4-turbo-preview' },
    { label: 'GPT-4', value: 'gpt-4' },
  ],
  'Google Gemini': [
    { label: 'Gemini 2.5 Flash (Exp)', value: 'gemini-2.5-flash-exp' },
    { label: 'Gemini 2.5 Flash', value: 'gemini-2.5-flash' },
    { label: 'Gemini 3 Pro', value: 'gemini-3-pro' },
  ],
  'Ollama': [],
};

export default function ConfigurePage() {
  const [loading, setLoading] = useState(true);
  const [awsProfile, setAwsProfile] = useState('');
  const [awsRegion, setAwsRegion] = useState('us-east-1');
  const [modelProvider, setModelProvider] = useState(null);
  const [modelId, setModelId] = useState('');
  const [modelIdOption, setModelIdOption] = useState(null);
  const [providerOptions, setProviderOptions] = useState([]);
  const [flashItems, setFlashItems] = useState([]);
  const [testingConnection, setTestingConnection] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      try {
        const [configData, providersData] = await Promise.all([
          getConfig(),
          getProviders(),
        ]);

        if (cancelled) return;

        setAwsProfile(configData.aws_profile || '');
        setAwsRegion(configData.aws_region || 'us-east-1');
        setModelId(configData.model_id || '');

        const options = (providersData.providers || []).map((p) => ({
          label: p,
          value: p,
        }));
        setProviderOptions(options);

        if (configData.model_provider) {
          setModelProvider({
            label: configData.model_provider,
            value: configData.model_provider,
          });
          // Set the model dropdown option if it matches a known model
          const models = PROVIDER_MODELS[configData.model_provider] || [];
          const match = models.find((m) => m.value === configData.model_id);
          if (match) {
            setModelIdOption(match);
          } else if (configData.model_id) {
            setModelIdOption({ label: configData.model_id, value: configData.model_id });
          }
        }
      } catch (err) {
        if (!cancelled) {
          setFlashItems([
            {
              type: 'error',
              dismissible: true,
              content: err.message || 'Failed to load configuration.',
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
    return () => { cancelled = true; };
  }, []);

  const buildTestConfig = () => ({
    provider: modelProvider?.value || '',
    model_id: modelId,
    aws_profile: awsProfile || null,
    aws_region: awsRegion || null,
  });

  const buildSaveConfig = () => ({
    provider: modelProvider?.value || '',
    model_id: modelId,
    aws_profile: awsProfile || null,
  });

  const addFlash = (type, content, id) => {
    setFlashItems((prev) => [
      ...prev.filter((i) => i.id !== id),
      {
        type,
        dismissible: true,
        content,
        id,
        onDismiss: () =>
          setFlashItems((items) => items.filter((i) => i.id !== id)),
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
        'test-result'
      );
    } catch (err) {
      addFlash('error', err.message || 'Connection test failed.', 'test-result');
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
        'save-result'
      );
    } catch (err) {
      addFlash('error', err.message || 'Failed to save configuration.', 'save-result');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <CloudscapeShell
        activePage="/configure"
        breadcrumbs={[
          { text: 'Home', href: '/' },
          { text: 'Configure', href: '/configure' },
        ]}
      >
        <Box textAlign="center" padding="xxl">
          <Spinner size="large" />
        </Box>
      </CloudscapeShell>
    );
  }

  return (
    <CloudscapeShell
      activePage="/configure"
      breadcrumbs={[
        { text: 'Home', href: '/' },
        { text: 'Configure', href: '/configure' },
      ]}
    >
      <SpaceBetween size="l">
        <Flashbar items={flashItems} />
        <Form
          header={<Header variant="h1">Configure</Header>}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button
                onClick={handleTestConnection}
                loading={testingConnection}
              >
                Test Connection
              </Button>
              <Button
                variant="primary"
                onClick={handleSave}
                loading={saving}
              >
                Save Configuration
              </Button>
            </SpaceBetween>
          }
        >
          <Container header={<Header variant="h2">AWS Settings</Header>}>
            <SpaceBetween size="l">
              <FormField label="AWS Profile">
                <Input
                  value={awsProfile}
                  onChange={({ detail }) => setAwsProfile(detail.value)}
                  placeholder="default"
                />
              </FormField>
              <FormField label="AWS Region">
                <Input
                  value={awsRegion}
                  onChange={({ detail }) => setAwsRegion(detail.value)}
                  placeholder="us-east-1"
                />
              </FormField>
              <FormField label="Model Provider">
                <Select
                  selectedOption={modelProvider}
                  onChange={({ detail }) => {
                    setModelProvider(detail.selectedOption);
                    setModelId('');
                    setModelIdOption(null);
                  }}
                  options={providerOptions}
                  placeholder="Select a provider"
                />
              </FormField>
              <FormField label="Model ID">
                {modelProvider && (PROVIDER_MODELS[modelProvider.value] || []).length > 0 ? (
                  <Select
                    selectedOption={modelIdOption}
                    onChange={({ detail }) => {
                      setModelIdOption(detail.selectedOption);
                      setModelId(detail.selectedOption.value);
                    }}
                    options={PROVIDER_MODELS[modelProvider.value]}
                    placeholder="Select a model"
                    filteringType="auto"
                  />
                ) : (
                  <Input
                    value={modelId}
                    onChange={({ detail }) => setModelId(detail.value)}
                    placeholder={modelProvider?.value === 'Ollama' ? 'e.g. llama3.1' : 'Enter model ID'}
                  />
                )}
              </FormField>
            </SpaceBetween>
          </Container>
        </Form>
      </SpaceBetween>
    </CloudscapeShell>
  );
}
