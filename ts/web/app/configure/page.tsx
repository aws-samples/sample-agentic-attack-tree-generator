'use client';

/**
 * Route "/configure" — TS/Next port of console-ui's pages/ConfigurePage.jsx.
 *
 * Model-provider / AWS credential settings plus the Langfuse tracing panel.
 *
 * Bedrock model ids are discovered LIVE from `GET /api/config/bedrock/models`
 * rather than hardcoded — the old static table had already drifted (Opus 5,
 * Sonnet 5 and Fable 5 were invocable but unlisted). PROVIDER_MODELS below
 * remains only for the providers that have no discovery endpoint (Anthropic
 * direct, OpenAI, Gemini) and as the Bedrock fallback if discovery fails.
 *
 * The Bedrock field is an Autosuggest, not a Select: with ~113 ids you want to
 * type-to-filter, and free text must stay possible so a brand-new model id can
 * be entered before any catalogue lists it.
 */

import { useState, useEffect } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Form from '@cloudscape-design/components/form';
import FormField from '@cloudscape-design/components/form-field';
import Input from '@cloudscape-design/components/input';
import Autosuggest, { type AutosuggestProps } from '@cloudscape-design/components/autosuggest';
import Select, { type SelectProps } from '@cloudscape-design/components/select';
import Button from '@cloudscape-design/components/button';
import Flashbar, { type FlashbarProps } from '@cloudscape-design/components/flashbar';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Container from '@cloudscape-design/components/container';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Box from '@cloudscape-design/components/box';
import Spinner from '@cloudscape-design/components/spinner';
import Toggle from '@cloudscape-design/components/toggle';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Link from '@cloudscape-design/components/link';
import AppShell from '@/components/AppShell';
import {
  getConfig,
  getProviders,
  getBedrockModels,
  testConnection,
  saveConfig,
  getLangfuseConfig,
  saveLangfuseConfig,
  testLangfuseConnection,
} from '@/api/client';
import type { BedrockModel } from '@threatforest/types';

interface ModelOption {
  label: string;
  value: string;
}

// Model options per provider — mirrors model_configs.py from the CLI.
const PROVIDER_MODELS: Record<string, ModelOption[]> = {
  'AWS Bedrock': [
    { label: 'Amazon Nova 2 Lite', value: 'global.amazon.nova-2-lite-v1:0' },
    { label: 'Claude Haiku 4.5', value: 'global.anthropic.claude-haiku-4-5-20251001-v1:0' },
    { label: 'Claude Sonnet 4.5', value: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0' },
    { label: 'Claude Sonnet 4.6', value: 'global.anthropic.claude-sonnet-4-6' },
    { label: 'Claude Opus 4.5', value: 'global.anthropic.claude-opus-4-5-20251101-v1:0' },
    { label: 'Claude Opus 4.6', value: 'global.anthropic.claude-opus-4-6-v1' },
    { label: 'Claude Opus 4.7', value: 'global.anthropic.claude-opus-4-7' },
    { label: 'Claude Opus 4.8', value: 'global.anthropic.claude-opus-4-8' },
  ],
  Anthropic: [
    { label: 'Claude 3 Sonnet', value: 'claude-3-sonnet-20240229' },
    { label: 'Claude 3 Opus', value: 'claude-3-opus-20240229' },
    { label: 'Claude 3 Haiku', value: 'claude-3-haiku-20240307' },
    { label: 'Claude Sonnet 4', value: 'claude-sonnet-4-20250514' },
  ],
  OpenAI: [
    { label: 'GPT-4o', value: 'gpt-4o' },
    { label: 'GPT-4 Turbo', value: 'gpt-4-turbo-preview' },
    { label: 'GPT-4', value: 'gpt-4' },
  ],
  'Google Gemini': [
    { label: 'Gemini 2.5 Flash (Exp)', value: 'gemini-2.5-flash-exp' },
    { label: 'Gemini 2.5 Flash', value: 'gemini-2.5-flash' },
    { label: 'Gemini 3 Pro', value: 'gemini-3-pro' },
  ],
  Ollama: [],
};

export default function ConfigurePage() {
  const [loading, setLoading] = useState(true);
  const [awsProfile, setAwsProfile] = useState('');
  const [awsRegion, setAwsRegion] = useState('us-east-1');
  const [modelProvider, setModelProvider] = useState<SelectProps.Option | null>(null);
  const [modelId, setModelId] = useState('');
  const [modelIdOption, setModelIdOption] = useState<SelectProps.Option | null>(null);
  const [providerOptions, setProviderOptions] = useState<SelectProps.Option[]>([]);
  // Live-discovered Bedrock catalogue.
  const [bedrockModels, setBedrockModels] = useState<BedrockModel[]>([]);
  const [bedrockSource, setBedrockSource] = useState<'live' | 'fallback' | null>(null);
  const [bedrockWarning, setBedrockWarning] = useState<string | null>(null);
  const [loadingModels, setLoadingModels] = useState(false);
  const [showAllProviders, setShowAllProviders] = useState(false);
  const [flashItems, setFlashItems] = useState<FlashbarProps.MessageDefinition[]>([]);
  const [testingConnection, setTestingConnection] = useState(false);
  const [saving, setSaving] = useState(false);
  const [langfuseEnabled, setLangfuseEnabled] = useState(false);
  const [langfusePublicKey, setLangfusePublicKey] = useState('');
  const [langfuseSecretKey, setLangfuseSecretKey] = useState('');
  const [langfuseSecretKeyConfigured, setLangfuseSecretKeyConfigured] = useState(false);
  const [langfuseHost, setLangfuseHost] = useState('https://cloud.langfuse.com');
  const [savingLangfuse, setSavingLangfuse] = useState(false);
  const [testingLangfuse, setTestingLangfuse] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      try {
        const [configData, providersData, langfuseData] = await Promise.all([
          getConfig(),
          getProviders(),
          getLangfuseConfig(),
        ]);

        if (cancelled) return;

        setAwsProfile(configData.aws_profile || '');
        // aws_region isn't part of the frozen ConfigResponse contract but the
        // legacy UI reads it when present; tolerate it via a loose read.
        setAwsRegion(
          (configData as { aws_region?: string }).aws_region || 'us-east-1',
        );
        setModelId(configData.model_id || '');

        setLangfuseEnabled(langfuseData.enabled || false);
        setLangfusePublicKey(langfuseData.public_key || '');
        setLangfuseSecretKeyConfigured(langfuseData.secret_key_configured || false);
        setLangfuseHost(langfuseData.host || 'https://cloud.langfuse.com');

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

  // Discover the Bedrock catalogue whenever Bedrock is the selected provider.
  // Re-runs on region change because the catalogue is region-specific — a model
  // listed in us-west-2 may not exist in eu-central-1.
  const isBedrock = modelProvider?.value === 'AWS Bedrock';
  useEffect(() => {
    if (!isBedrock) return;
    let cancelled = false;

    async function loadModels() {
      setLoadingModels(true);
      try {
        const data = await getBedrockModels(awsRegion ? { region: awsRegion } : {});
        if (cancelled) return;
        setBedrockModels(data.models);
        setBedrockSource(data.source);
        setBedrockWarning(data.warning);
      } catch (err) {
        // The endpoint degrades to a fallback list rather than failing, so
        // reaching here means the server itself is unreachable. Surface it in
        // the field's own status area instead of a page-level error, and leave
        // the input usable as free text.
        if (!cancelled) {
          setBedrockModels([]);
          setBedrockSource('fallback');
          setBedrockWarning(
            `Could not load the model list (${(err as Error).message}). You can still type a model id.`,
          );
        }
      } finally {
        if (!cancelled) setLoadingModels(false);
      }
    }

    loadModels();
    return () => {
      cancelled = true;
    };
  }, [isBedrock, awsRegion]);

  const buildTestConfig = () => ({
    provider: modelProvider?.value || '',
    model_id: modelId,
    aws_profile: awsProfile || null,
    aws_region: awsRegion || null,
    // The connection-test contract expects an explicit api_key; this UI has no
    // api-key field for the model provider, so send null (as before).
    api_key: null,
  });

  const buildSaveConfig = () => ({
    provider: modelProvider?.value || '',
    model_id: modelId,
    aws_profile: awsProfile || null,
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
            provider: modelProvider?.value || '',
            model_id: modelId,
            aws_profile: awsProfile || '',
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

  const handleSaveLangfuse = async () => {
    setSavingLangfuse(true);
    try {
      const result = await saveLangfuseConfig({
        enabled: langfuseEnabled,
        public_key: langfusePublicKey || null,
        secret_key: langfuseSecretKey || null,
        host: langfuseHost,
      });
      addFlash(
        result.success ? 'success' : 'error',
        result.message || (result.success ? 'Langfuse configuration saved.' : 'Save failed.'),
        'langfuse-save-result',
      );
      if (result.success) setLangfuseSecretKey('');
    } catch (err) {
      addFlash(
        'error',
        (err as Error).message || 'Failed to save Langfuse configuration.',
        'langfuse-save-result',
      );
    } finally {
      setSavingLangfuse(false);
    }
  };

  const handleTestLangfuse = async () => {
    setTestingLangfuse(true);
    try {
      const result = await testLangfuseConnection({
        enabled: true,
        public_key: langfusePublicKey || null,
        secret_key: langfuseSecretKey || null,
        host: langfuseHost,
      });
      addFlash(result.success ? 'success' : 'error', result.message, 'langfuse-test-result');
    } catch (err) {
      addFlash(
        'error',
        (err as Error).message || 'Langfuse connection test failed.',
        'langfuse-test-result',
      );
    } finally {
      setTestingLangfuse(false);
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

  const providerModels = modelProvider ? PROVIDER_MODELS[modelProvider.value ?? ''] || [] : [];

  // Bedrock options, grouped so the models this pipeline is tuned for surface
  // first. Non-recommended providers (Qwen, Mistral, DeepSeek, ...) are hidden
  // behind a toggle rather than dropped: they are invocable, but the agent
  // prompts and the temperature handling in the engine are Claude-shaped, so
  // they tend to yield weaker threat models.
  const bedrockOptions: AutosuggestProps.Options = (() => {
    const visible = showAllProviders ? bedrockModels : bedrockModels.filter((m) => m.recommended);
    const describe = (m: BedrockModel): string => {
      const bits: string[] = [m.provider];
      if (m.is_inference_profile) bits.push('cross-region');
      if (m.lifecycle === 'LEGACY') {
        const when = m.end_of_life ? ` — EOL ${m.end_of_life.slice(0, 10)}` : '';
        bits.push(`LEGACY${when}`);
      }
      return bits.join(' · ');
    };
    // Group by "recommended" so a long list stays scannable while typing.
    if (showAllProviders) {
      const rec = visible.filter((m) => m.recommended);
      const other = visible.filter((m) => !m.recommended);
      const groups: AutosuggestProps.OptionGroup[] = [];
      if (rec.length > 0) {
        groups.push({
          label: 'Recommended (Anthropic / Amazon)',
          options: rec.map((m) => ({ value: m.id, description: describe(m) })),
        });
      }
      if (other.length > 0) {
        groups.push({
          label: 'Other providers',
          options: other.map((m) => ({ value: m.id, description: describe(m) })),
        });
      }
      return groups;
    }
    return visible.map((m) => ({ value: m.id, description: describe(m) }));
  })();

  // Warn when the chosen id is on its way out — the whole point of reading
  // lifecycle from the API instead of hardcoding a list.
  const selectedBedrockModel = bedrockModels.find((m) => m.id === modelId) ?? null;
  const bedrockFieldStatus = ((): { type: 'error' | 'warning' | 'info'; text: string } | null => {
    if (!isBedrock) return null;
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
      const shown = showAllProviders ? bedrockModels.length : bedrockOptions.length;
      return {
        type: 'info',
        text: `${shown} of ${bedrockModels.length} models available in ${awsRegion || 'the default region'}.`,
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
            description="Manage your model provider, AWS credentials, and observability integrations."
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
                  disabled={!modelProvider?.value || !modelId}
                  iconName="status-positive"
                >
                  Test Connection
                </Button>
                <Button
                  variant="primary"
                  onClick={handleSave}
                  loading={saving}
                  disabled={!modelProvider?.value || !modelId}
                >
                  Save Configuration
                </Button>
              </SpaceBetween>
            }
          >
            <SpaceBetween size="l">
              <Container header={<Header variant="h2">Model settings</Header>}>
                <SpaceBetween size="l">
                  <ColumnLayout columns={2}>
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
                    <FormField
                      label="Model ID"
                      description={
                        isBedrock
                          ? 'Type to search the live Bedrock catalogue, or enter any model id directly.'
                          : undefined
                      }
                      {...(bedrockFieldStatus?.type === 'warning'
                        ? { warningText: bedrockFieldStatus.text }
                        : {})}
                      {...(bedrockFieldStatus?.type === 'info'
                        ? { constraintText: bedrockFieldStatus.text }
                        : {})}
                      secondaryControl={
                        isBedrock ? (
                          <Button
                            iconName="refresh"
                            loading={loadingModels}
                            ariaLabel="Refresh the Bedrock model list"
                            onClick={() => {
                              setLoadingModels(true);
                              getBedrockModels({
                                ...(awsRegion ? { region: awsRegion } : {}),
                                refresh: true,
                              })
                                .then((data) => {
                                  setBedrockModels(data.models);
                                  setBedrockSource(data.source);
                                  setBedrockWarning(data.warning);
                                })
                                .catch((err: Error) => setBedrockWarning(err.message))
                                .finally(() => setLoadingModels(false));
                            }}
                          />
                        ) : undefined
                      }
                    >
                      {isBedrock ? (
                        // Autosuggest (not Select): free text stays valid, so a
                        // model id newer than the catalogue can still be entered.
                        <Autosuggest
                          value={modelId}
                          onChange={({ detail }) => setModelId(detail.value)}
                          options={bedrockOptions}
                          enteredTextLabel={(value) => `Use "${value}"`}
                          placeholder="Search or type a Bedrock model id"
                          loadingText="Loading models…"
                          statusType={loadingModels ? 'loading' : 'finished'}
                          empty="No matching models — the id can still be typed in full."
                          filteringType="auto"
                        />
                      ) : modelProvider && providerModels.length > 0 ? (
                        <Select
                          selectedOption={modelIdOption}
                          onChange={({ detail }) => {
                            setModelIdOption(detail.selectedOption);
                            setModelId(detail.selectedOption.value ?? '');
                          }}
                          options={providerModels}
                          placeholder="Select a model"
                          filteringType="auto"
                        />
                      ) : (
                        <Input
                          value={modelId}
                          onChange={({ detail }) => setModelId(detail.value)}
                          placeholder={
                            modelProvider?.value === 'Ollama' ? 'e.g. llama3.1' : 'Enter model ID'
                          }
                        />
                      )}
                    </FormField>
                  </ColumnLayout>
                  {isBedrock && (
                    <Toggle
                      checked={showAllProviders}
                      onChange={({ detail }) => setShowAllProviders(detail.checked)}
                    >
                      Include non-Anthropic providers (Qwen, Mistral, DeepSeek, …) — invocable, but
                      the pipeline&apos;s prompts are tuned for Claude
                    </Toggle>
                  )}
                  <ColumnLayout columns={2}>
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
                  </ColumnLayout>
                </SpaceBetween>
              </Container>
            </SpaceBetween>
          </Form>

          {/* Langfuse Tracing */}
          <Container
            header={
              <Header
                variant="h2"
                description="Trace and evaluate threat modeling workflows with Langfuse observability."
                actions={
                  <SpaceBetween direction="horizontal" size="xs">
                    <Toggle
                      checked={langfuseEnabled}
                      onChange={({ detail }) => setLangfuseEnabled(detail.checked)}
                    >
                      {langfuseEnabled ? 'Enabled' : 'Disabled'}
                    </Toggle>
                  </SpaceBetween>
                }
                info={
                  <Link variant="info" href="https://langfuse.com/docs" external>
                    Info
                  </Link>
                }
              >
                Langfuse tracing
              </Header>
            }
          >
            <SpaceBetween size="l">
              {!langfuseEnabled ? (
                <Box color="text-status-inactive" padding={{ vertical: 's' }}>
                  <StatusIndicator type="stopped">
                    Langfuse tracing is disabled. Enable it to trace and score your threat modeling
                    runs.
                  </StatusIndicator>
                </Box>
              ) : (
                <>
                  <ColumnLayout columns={2}>
                    <FormField label="Public Key">
                      <Input
                        value={langfusePublicKey}
                        onChange={({ detail }) => setLangfusePublicKey(detail.value)}
                        placeholder="pk-lf-..."
                      />
                    </FormField>
                    <FormField
                      label="Secret Key"
                      description={
                        langfuseSecretKeyConfigured && !langfuseSecretKey
                          ? 'A secret key is already configured. Enter a new value to replace it.'
                          : 'Required when enabling Langfuse.'
                      }
                    >
                      <Input
                        value={langfuseSecretKey}
                        onChange={({ detail }) => setLangfuseSecretKey(detail.value)}
                        placeholder={langfuseSecretKeyConfigured ? '••••••••••••••••' : 'sk-lf-...'}
                        type="password"
                      />
                    </FormField>
                  </ColumnLayout>
                  <FormField label="Host">
                    <Input
                      value={langfuseHost}
                      onChange={({ detail }) => setLangfuseHost(detail.value)}
                      placeholder="https://cloud.langfuse.com"
                    />
                  </FormField>
                </>
              )}
              <Box float="right">
                <SpaceBetween direction="horizontal" size="xs">
                  {langfuseEnabled && (
                    <Button
                      onClick={handleTestLangfuse}
                      loading={testingLangfuse}
                      iconName="status-positive"
                    >
                      Test Connection
                    </Button>
                  )}
                  <Button variant="primary" onClick={handleSaveLangfuse} loading={savingLangfuse}>
                    Save Langfuse Settings
                  </Button>
                </SpaceBetween>
              </Box>
            </SpaceBetween>
          </Container>
        </SpaceBetween>
      </ContentLayout>
    </AppShell>
  );
}
