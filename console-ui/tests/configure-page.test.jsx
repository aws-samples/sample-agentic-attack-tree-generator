import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ConfigurePage from '../src/pages/ConfigurePage.jsx';

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../src/api-client', () => ({
  getConfig: vi.fn(),
  getProviders: vi.fn(),
  testConnection: vi.fn(),
  saveConfig: vi.fn(),
  getLangfuseConfig: vi.fn(),
  saveLangfuseConfig: vi.fn(),
  testLangfuseConnection: vi.fn(),
}));

import { getConfig, getProviders, testConnection, saveConfig, getLangfuseConfig, saveLangfuseConfig } from '../src/api-client';

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/configure']}>
      <ConfigurePage />
    </MemoryRouter>
  );
}

describe('ConfigurePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getConfig.mockResolvedValue({
      aws_profile: 'my-profile',
      aws_region: 'us-west-2',
      model_provider: 'AWS Bedrock',
      model_id: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
    });
    getProviders.mockResolvedValue({
      providers: ['AWS Bedrock', 'Anthropic', 'OpenAI', 'Google Gemini', 'Ollama'],
    });
    getLangfuseConfig.mockResolvedValue({
      enabled: false,
      public_key: null,
      host: 'https://cloud.langfuse.com',
    });
  });

  it('renders within CloudscapeShell with activePage="/configure"', async () => {
    const { container } = renderPage();
    await waitFor(() => {
      const activeLinks = container.querySelectorAll('[aria-current="page"]');
      expect(activeLinks.length).toBeGreaterThan(0);
      const hrefs = Array.from(activeLinks).map((el) => el.getAttribute('href'));
      expect(hrefs).toContain('/configure');
    });
  });

  it('transitions from loading to form after data loads', async () => {
    renderPage();
    // After data loads, the form should be visible
    await waitFor(() => {
      expect(screen.getAllByText('AWS Profile').length).toBeGreaterThan(0);
      expect(screen.getAllByText('AWS Region').length).toBeGreaterThan(0);
    });
  });

  it('fetches config and providers on mount', async () => {
    renderPage();
    await waitFor(() => {
      expect(getConfig).toHaveBeenCalledTimes(1);
      expect(getProviders).toHaveBeenCalledTimes(1);
    });
  });

  it('pre-populates form fields with fetched config values', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Configure').length).toBeGreaterThan(0);
    });
    // Check that the input values are pre-populated
    const inputs = document.querySelectorAll('input');
    const values = Array.from(inputs).map((i) => i.value);
    expect(values).toContain('my-profile');
    expect(values).toContain('us-west-2');
    // Model ID is now a Select dropdown — check the selected option text is visible
    expect(screen.getAllByText('Claude Sonnet 4.5').length).toBeGreaterThan(0);
  });

  it('renders form field labels', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('AWS Profile').length).toBeGreaterThan(0);
      expect(screen.getAllByText('AWS Region').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Model Provider').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Model ID').length).toBeGreaterThan(0);
    });
  });

  it('renders Test Connection and Save Configuration buttons', async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Test Connection').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Save Configuration').length).toBeGreaterThan(0);
    });
  });

  it('calls testConnection and shows success flashbar', async () => {
    testConnection.mockResolvedValue({ success: true, message: 'Connection OK' });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Test Connection').length).toBeGreaterThan(0);
    });

    const buttons = screen.getAllByRole('button');
    const testBtn = buttons.find((b) => b.textContent.trim() === 'Test Connection');
    fireEvent.click(testBtn);

    await waitFor(() => {
      expect(testConnection).toHaveBeenCalledWith({
        aws_profile: 'my-profile',
        aws_region: 'us-west-2',
        provider: 'AWS Bedrock',
        model_id: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
      });
      expect(screen.getAllByText('Connection OK').length).toBeGreaterThan(0);
    });
  });

  it('calls saveConfig and shows success flashbar', async () => {
    saveConfig.mockResolvedValue({ success: true, message: 'Saved successfully' });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Save Configuration').length).toBeGreaterThan(0);
    });

    const buttons = screen.getAllByRole('button');
    const saveBtn = buttons.find((b) => b.textContent.trim() === 'Save Configuration');
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(saveConfig).toHaveBeenCalledWith({
        aws_profile: 'my-profile',
        provider: 'AWS Bedrock',
        model_id: 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
      });
      expect(screen.getAllByText('Saved successfully').length).toBeGreaterThan(0);
    });
  });

  it('shows error flashbar when testConnection fails', async () => {
    testConnection.mockRejectedValue(new Error('Connection refused'));
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Test Connection').length).toBeGreaterThan(0);
    });

    const buttons = screen.getAllByRole('button');
    const testBtn = buttons.find((b) => b.textContent.trim() === 'Test Connection');
    fireEvent.click(testBtn);

    await waitFor(() => {
      expect(screen.getAllByText('Connection refused').length).toBeGreaterThan(0);
    });
  });

  it('shows error flashbar when saveConfig fails', async () => {
    saveConfig.mockRejectedValue(new Error('Save failed'));
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Save Configuration').length).toBeGreaterThan(0);
    });

    const buttons = screen.getAllByRole('button');
    const saveBtn = buttons.find((b) => b.textContent.trim() === 'Save Configuration');
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(screen.getAllByText('Save failed').length).toBeGreaterThan(0);
    });
  });

  it('shows error flashbar when initial config load fails', async () => {
    getConfig.mockRejectedValue(new Error('Failed to load'));
    getProviders.mockResolvedValue({ providers: [] });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Failed to load').length).toBeGreaterThan(0);
    });
  });

  it('renders breadcrumbs with Home and Configure', async () => {
    const { container } = renderPage();
    await waitFor(() => {
      const breadcrumbLinks = container.querySelectorAll(
        '[class*="breadcrumb"] a, [class*="Breadcrumb"] a'
      );
      const texts = Array.from(breadcrumbLinks).map((el) => el.textContent);
      expect(texts).toContain('Home');
    });
  });

  it('defaults AWS Region to us-east-1 when config has no region', async () => {
    getConfig.mockResolvedValue({
      aws_profile: '',
      model_provider: '',
      model_id: '',
    });
    renderPage();
    await waitFor(() => {
      expect(screen.getAllByText('Configure').length).toBeGreaterThan(0);
    });
    const inputs = document.querySelectorAll('input');
    const values = Array.from(inputs).map((i) => i.value);
    expect(values).toContain('us-east-1');
  });
});
