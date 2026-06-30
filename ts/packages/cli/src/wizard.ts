/**
 * Interactive wizard — TS port of `CLIWizard` from
 * `src/threatforest/modules/cli/wizard.py`, using @inquirer/prompts in place of
 * questionary. Covers: first-run config check/init, mode selection, project-path
 * picker, framework checklist, threat-statement preference, credential update,
 * and model-settings editing.
 *
 * @inquirer/prompts has no `path` prompt, so directory/file pickers use `input`
 * with the same expand-resolve-validate loop the Python ran (tab-autocomplete
 * is the only feature dropped — noted as a caveat).
 */
import { existsSync, statSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { confirm, input, password, select, checkbox } from '@inquirer/prompts';
import pc from 'picocolors';

import { config } from '@threatforest/engine';
import * as display from './display.js';
import { ConfigManager, defaultConfigData } from './config-manager.js';
import { EnvManager } from './env-manager.js';
import { BEDROCK_MODELS } from './model-configs.js';

/** Expand a leading `~` and resolve against cwd, mirroring Path.expanduser().resolve(). */
function expandResolve(p: string): string {
  let out = p;
  if (out === '~') out = homedir();
  else if (out.startsWith('~/')) out = join(homedir(), out.slice(2));
  return isAbsolute(out) ? out : resolve(process.cwd(), out);
}

export type SelectedMode = 'full' | 'credentials' | 'model_settings' | 'exit';

export class CLIWizard {
  private readonly cfgMgr = new ConfigManager();
  private readonly env = new EnvManager();

  /**
   * First-run check: if config.yaml or .env is missing, offer interactive setup.
   * Returns true if a config was created. (Port of check_and_init_config.)
   */
  async checkAndInitConfig(): Promise<boolean> {
    const configMissing = !existsSync(this.cfgMgr.userConfigFile);
    const envMissing = !existsSync(this.env.envFile);

    if (!configMissing) this.cfgMgr.migrateConfig();
    if (!configMissing && !envMissing) return false;

    display.blank();
    display.panel(
      `${pc.bold(pc.blue('🌳 Welcome to ThreatForest!'))}\n\n` +
        `${pc.cyan('It looks like this is your first time here.')}\n\n` +
        "Let's set up your configuration...",
      { color: pc.blue },
    );
    display.blank();

    const setupChoice = await select({
      message: 'How would you like to proceed?',
      choices: [
        { name: '🔧 Configure now (choose provider, model, etc.)', value: 'configure' },
        { name: '⚡ Skip setup (use AWS Bedrock + Claude Sonnet defaults)', value: 'skip' },
      ],
    });

    if (setupChoice === 'skip') {
      display.blank();
      display.print(`${pc.green('✓')} Using default configuration (AWS Bedrock + Claude Sonnet)`);
      display.print(pc.dim("You can customize later by selecting 'Update Configuration'"));
      display.blank();
      return false;
    }

    display.blank();
    display.print(pc.bold(pc.cyan("Let's configure ThreatForest...")));
    display.blank();

    // 1. Provider selection
    let provider = await select({
      message: 'Select your AI provider:',
      choices: [
        { name: 'AWS Bedrock', value: 'AWS Bedrock' },
        { name: 'Anthropic (Experimental)', value: 'Anthropic' },
        { name: 'OpenAI (Experimental)', value: 'OpenAI' },
        { name: 'Google Gemini (Experimental)', value: 'Google Gemini' },
        { name: 'Ollama (Experimental)', value: 'Ollama' },
        { name: 'LiteLLM (Experimental)', value: 'LiteLLM' },
        { name: 'LlamaAPI (Experimental)', value: 'LlamaAPI' },
      ],
    });
    provider = provider.replace(' (Experimental)', '');

    // 2. Model/endpoint selection
    let modelId = '';
    let ollamaHost: string | null = null;

    if (provider === 'AWS Bedrock') {
      const choice = await select({
        message: 'Select model:',
        choices: [
          ...BEDROCK_MODELS.map((m) => ({ name: m, value: m })),
          { name: 'Other (enter custom model ID)', value: '__other__' },
        ],
      });
      modelId = choice === '__other__' ? await input({ message: 'Enter Bedrock model ID:', default: '' }) : choice;
    } else if (provider === 'Ollama') {
      modelId = await input({ message: 'Enter Ollama model name:', default: 'llama3.1' });
      ollamaHost = await input({ message: 'Ollama host (optional):', default: 'http://localhost:11434' });
    } else {
      modelId = await input({ message: `Enter ${provider} model ID:`, default: '' });
    }

    // 3. Credentials
    this.env.ensureExists();
    if (provider === 'AWS Bedrock') {
      const authChoice = await select({
        message: 'How do you want to authenticate with AWS?',
        choices: [
          { name: '🔑 AWS Profile (recommended)', value: 'profile' },
          { name: '🔐 Access Keys', value: 'access_keys' },
        ],
      });
      if (authChoice === 'profile') {
        const awsProfile = await input({ message: 'AWS Profile name:', default: 'default' });
        const awsRegion = await input({ message: 'AWS Region:', default: 'us-east-1' });
        this.env.setValue('AWS_PROFILE', awsProfile);
        this.env.setValue('AWS_REGION', awsRegion);
        display.blank();
        display.print(`${pc.green('✓')} AWS Profile configured: ${awsProfile}`);
        display.print(`${pc.green('✓')} AWS Region configured: ${awsRegion}`);
      } else {
        const accessKeyId = await password({ message: 'AWS Access Key ID:' });
        const secretAccessKey = await password({ message: 'AWS Secret Access Key:' });
        const awsRegion = await input({ message: 'AWS Region:', default: 'us-east-1' });
        this.env.setValue('AWS_ACCESS_KEY_ID', accessKeyId);
        this.env.setValue('AWS_SECRET_ACCESS_KEY', secretAccessKey);
        this.env.setValue('AWS_REGION', awsRegion);
        display.blank();
        display.print(`${pc.green('✓')} AWS Access Keys configured`);
        display.print(`${pc.green('✓')} AWS Region configured: ${awsRegion}`);
      }
      // NOTE: aws_validator connection test is stubbed (see caveats).
    } else {
      const apiKeyVar: Record<string, string> = {
        Anthropic: 'ANTHROPIC_API_KEY',
        OpenAI: 'OPENAI_API_KEY',
        'Google Gemini': 'GEMINI_API_KEY',
        LiteLLM: 'LITELLM_API_KEY',
        LlamaAPI: 'LLAMAAPI_API_KEY',
      };
      const keyVar = apiKeyVar[provider];
      if (keyVar && !this.env.getValue(keyVar)) {
        display.blank();
        display.print(pc.yellow(`⚠️  ${keyVar} not found in .env`));
        const apiKey = await password({ message: `Enter your ${provider} API key:` });
        if (apiKey) {
          this.env.setValue(keyVar, apiKey);
          display.print(`${pc.green('✓')} API key saved to .env`);
        }
      }
    }

    // 4. Build + save config (start from the canonical default, swap provider block).
    const configData = defaultConfigData();
    for (const p of ['bedrock', 'anthropic', 'openai', 'gemini', 'ollama', 'litellm', 'llamaapi', 'sagemaker']) {
      delete configData[p];
    }
    const blockKey: Record<string, string> = {
      'AWS Bedrock': 'bedrock',
      Anthropic: 'anthropic',
      OpenAI: 'openai',
      'Google Gemini': 'gemini',
      Ollama: 'ollama',
      LiteLLM: 'litellm',
      LlamaAPI: 'llamaapi',
    };
    const key = blockKey[provider]!;
    configData[key] = provider === 'Ollama' ? { host: ollamaHost, model_id: modelId } : { model_id: modelId };

    mkdirSync(this.cfgMgr.userConfigDir, { recursive: true });
    writeFileSync(this.cfgMgr.userConfigFile, stringifyYaml(configData));

    display.blank();
    display.print(`${pc.green('✓')} Configuration created at ./.threatforest/config.yaml`);
    display.blank();
    display.print(pc.bold(pc.cyan('Active Configuration:')));
    display.print(`  Provider: ${pc.yellow(provider)}`);
    if (modelId) display.print(`  Model: ${pc.yellow(modelId)}`);
    if (ollamaHost) display.print(`  Host: ${pc.yellow(ollamaHost)}`);
    display.blank();
    return true;
  }

  /** Step 1/5 — action menu. (Port of select_mode.) */
  async selectMode(): Promise<SelectedMode> {
    display.showStepHeader(1, 5, 'Select Action');
    const mode = await select<SelectedMode | 'separator'>({
      message: 'What would you like to do?',
      choices: [
        { name: '🌳 Generate Attack Trees & Analysis', value: 'full' },
        { name: '🔑 Update Credentials (returns to menu)', value: 'credentials' },
        { name: '⚙️  Configure Model Settings (returns to menu)', value: 'model_settings' },
        { name: '🚪 Exit Application', value: 'exit' },
      ],
    });
    return mode === 'separator' ? 'exit' : mode;
  }

  /** Step 2/5 — project directory picker with validation loop. */
  async getProjectPath(): Promise<string> {
    display.showStepHeader(2, 5, 'Select Project Directory');
    display.print(pc.dim('📂 Choose the directory where your application information is stored'));
    display.print(pc.dim('   (README, architecture diagrams, dataflow diagrams, etc.)'));
    display.blank();

    for (;;) {
      const pathStr = await input({ message: 'Project directory path:', default: '' });
      const projectPath = expandResolve(pathStr);
      if (existsSync(projectPath) && statSync(projectPath).isDirectory()) {
        display.print(`${pc.green('✓')} Valid directory: ${pc.cyan(projectPath)}`);
        display.blank();
        return projectPath;
      }
      display.panel(`${pc.red('Directory not found:')} ${pc.yellow(projectPath)}`, { color: pc.red });
      display.blank();
    }
  }

  /** Step 3/5 — framework checklist (all checked by default). */
  async selectFrameworks(): Promise<string[]> {
    const frameworks = config.frameworks;
    display.showStepHeader(3, 5, 'Select Threat Frameworks');
    display.print(pc.dim('Choose which knowledge bases to map attack steps against.'));
    display.print(pc.dim('All frameworks are selected by default.'));
    display.blank();

    const descriptions: Record<string, string> = {
      attack: '835 techniques — cloud, network, endpoint',
      atlas: 'AI/ML adversarial threats',
      wiz: 'cloud threat landscape',
    };
    let selected = await checkbox({
      message: 'Which frameworks should ThreatForest map to?',
      choices: Object.entries(frameworks).map(([k, fw]) => ({
        name: `${fw.name} (${descriptions[k] ?? ''})`,
        value: k,
        checked: true,
      })),
      validate: (xs) => (xs.length > 0 ? true : 'Select at least one framework'),
    });
    if (!selected.length) selected = Object.keys(frameworks);

    const names = selected.filter((k) => k in frameworks).map((k) => frameworks[k]!.name);
    display.print(`${pc.green('✓')} Frameworks: ${pc.cyan(names.join(', '))}`);
    display.blank();
    return selected;
  }

  /** Step 4/5 — existing-threats preference. Returns [hasThreats, filePath]. */
  async askThreatStatementPreference(): Promise<[boolean, string | null]> {
    display.showStepHeader(4, 5, 'Threat Statements');
    display.panel(
      `${pc.bold(pc.blue('📋 Threat Statements'))}\n\n` +
        `${pc.dim('Do you have existing threat statements for this project?')}\n` +
        `${pc.dim("If not, we'll generate them automatically using AI analysis.")}`,
      { color: pc.blue },
    );
    display.blank();

    const hasThreats = await confirm({ message: 'Do you have existing threat statements?', default: false });
    if (!hasThreats) {
      display.print(`${pc.cyan('✓')} Threat statements will be auto-generated`);
      display.blank();
      return [false, null];
    }

    display.print(pc.dim('Please provide the path to your threat statements file'));
    display.print(pc.dim('Supported formats: JSON, YAML, Markdown, ThreatComposer (.tc.json)'));
    display.blank();

    for (;;) {
      const pathStr = await input({ message: 'Threat statements file path:', default: '' });
      if (!pathStr) {
        display.print(pc.yellow('Please provide a file path or press Ctrl+C to skip'));
        display.blank();
        continue;
      }
      const threatPath = expandResolve(pathStr);
      if (existsSync(threatPath) && statSync(threatPath).isFile()) {
        display.print(`${pc.green('✓')} Using threat file: ${pc.cyan(threatPath)}`);
        display.blank();
        return [true, threatPath];
      }
      display.panel(`${pc.red('File not found:')} ${pc.yellow(threatPath)}`, { color: pc.red });
      display.blank();
    }
  }

  /** Confirmation prompt (default yes), matching confirm_continue. */
  async confirmContinue(message: string): Promise<boolean> {
    display.blank();
    return confirm({ message, default: true });
  }

  /** Mode info panel for "full" (port of show_mode_info). */
  showModeInfo(mode: SelectedMode): void {
    if (mode !== 'full') return;
    display.blank();
    display.panel(
      `${pc.bold(pc.blue('🌳 Attack Tree Generation & Analysis'))}\n\n` +
        'This will execute a complete security analysis:\n' +
        `  ${pc.cyan('1.')} Analyze project and extract security context\n` +
        `  ${pc.cyan('2.')} Generate comprehensive attack trees\n` +
        `  ${pc.cyan('3.')} Enrich with MITRE ATT&CK TTP mappings\n` +
        `  ${pc.cyan('4.')} Add mitigation recommendations\n\n` +
        `${pc.dim('Estimated time: 5-15 minutes depending on project size')}`,
      { color: pc.blue },
    );
    display.blank();
  }

  /** Credential-update submenu (port of update_credentials). */
  async updateCredentials(): Promise<boolean> {
    this.env.ensureExists();
    display.blank();
    display.print(pc.bold(pc.cyan('Select provider to configure:')));
    display.blank();

    const status = (configured: boolean, label: string, suffix: string): string =>
      `${configured ? '✓' : '○'} ${label} [${suffix}]`;

    const awsLabel = this.env.getValue('AWS_PROFILE')
      ? status(true, 'AWS Bedrock', `Profile: ${this.env.getValue('AWS_PROFILE')}`)
      : this.env.getValue('AWS_ACCESS_KEY_ID')
        ? status(true, 'AWS Bedrock', 'Access Keys')
        : status(false, 'AWS Bedrock', 'Not configured');

    const apiChoice = (label: string, key: string, value: string): { name: string; value: string } => ({
      name: this.env.getValue(key) ? status(true, label, 'API Key configured') : status(false, label, 'Not configured'),
      value,
    });

    const langfuseConfigured =
      this.env.getValue('LANGFUSE_ENABLED') === 'true' && !!this.env.getValue('LANGFUSE_PUBLIC_KEY');

    const provider = await select({
      message: 'Select provider:',
      choices: [
        { name: awsLabel, value: 'AWS Bedrock' },
        apiChoice('Anthropic (Experimental)', 'ANTHROPIC_API_KEY', 'Anthropic'),
        apiChoice('OpenAI (Experimental)', 'OPENAI_API_KEY', 'OpenAI'),
        apiChoice('Google Gemini (Experimental)', 'GEMINI_API_KEY', 'Google Gemini'),
        apiChoice('LiteLLM (Experimental)', 'LITELLM_API_KEY', 'LiteLLM'),
        apiChoice('LlamaAPI (Experimental)', 'LLAMAAPI_API_KEY', 'LlamaAPI'),
        { name: '✓ Ollama (Experimental) [No credentials needed]', value: 'Ollama' },
        {
          name: langfuseConfigured ? '✓ Langfuse Tracing [Enabled]' : '○ Langfuse Tracing [Not configured]',
          value: 'Langfuse',
        },
        { name: '← Cancel', value: 'cancel' },
      ],
    });

    if (provider === 'cancel') {
      display.blank();
      display.print(pc.dim('Cancelled credential update'));
      display.blank();
      return false;
    }

    display.blank();
    display.print(pc.bold(pc.cyan(`Configuring: ${provider}`)));
    display.blank();

    if (provider === 'AWS Bedrock') {
      const authChoice = await select({
        message: 'How do you want to authenticate with AWS?',
        choices: [
          { name: '🔑 AWS Profile (recommended)', value: 'profile' },
          { name: '🔐 Access Keys', value: 'access_keys' },
        ],
      });
      if (authChoice === 'profile') {
        const currentProfile = this.env.getValue('AWS_PROFILE') ?? 'default';
        const profile = await input({ message: `AWS Profile name (current: ${currentProfile}):`, default: currentProfile });
        const currentRegion = this.env.getValue('AWS_REGION') ?? 'us-east-1';
        const region = await input({ message: `AWS Region (current: ${currentRegion}):`, default: currentRegion });
        this.env.setValue('AWS_PROFILE', profile);
        this.env.setValue('AWS_REGION', region);
        if (this.env.getValue('AWS_ACCESS_KEY_ID')) this.env.setValue('AWS_ACCESS_KEY_ID', '');
        if (this.env.getValue('AWS_SECRET_ACCESS_KEY')) this.env.setValue('AWS_SECRET_ACCESS_KEY', '');
        display.blank();
        display.print(`${pc.green('✓')} AWS Profile configured: ${profile}`);
        display.print(`${pc.green('✓')} AWS Region configured: ${region}`);
      } else {
        const accessKeyId = await password({ message: 'AWS Access Key ID:' });
        const secretAccessKey = await password({ message: 'AWS Secret Access Key:' });
        const currentRegion = this.env.getValue('AWS_REGION') ?? 'us-east-1';
        const region = await input({ message: `AWS Region (current: ${currentRegion}):`, default: currentRegion });
        this.env.setValue('AWS_ACCESS_KEY_ID', accessKeyId);
        this.env.setValue('AWS_SECRET_ACCESS_KEY', secretAccessKey);
        this.env.setValue('AWS_REGION', region);
        if (this.env.getValue('AWS_PROFILE')) this.env.setValue('AWS_PROFILE', '');
        display.blank();
        display.print(`${pc.green('✓')} AWS Access Keys configured`);
        display.print(`${pc.green('✓')} AWS Region configured: ${region}`);
      }
    } else if (['Anthropic', 'OpenAI', 'Google Gemini', 'LiteLLM', 'LlamaAPI'].includes(provider)) {
      const keyVarMap: Record<string, string> = {
        Anthropic: 'ANTHROPIC_API_KEY',
        OpenAI: 'OPENAI_API_KEY',
        'Google Gemini': 'GEMINI_API_KEY',
        LiteLLM: 'LITELLM_API_KEY',
        LlamaAPI: 'LLAMAAPI_API_KEY',
      };
      const keyVar = keyVarMap[provider]!;
      const apiKey = await password({ message: `Enter ${provider} API key:` });
      if (apiKey) {
        this.env.setValue(keyVar, apiKey);
        display.blank();
        display.print(`${pc.green('✓')} ${provider} API key configured`);
      }
    } else if (provider === 'Ollama') {
      display.blank();
      display.print(pc.dim("Ollama runs locally and doesn't require credentials"));
      display.print(pc.dim("If you need to change the host, use 'Configure Model Settings'"));
    } else if (provider === 'Langfuse') {
      await this.configureLangfuseInteractive();
    }

    display.blank();
    display.print(`${pc.green('✓')} Credentials updated successfully!`);
    display.print(pc.dim('Changes will take effect immediately'));
    display.blank();
    return true;
  }

  /** Shared Langfuse interactive setup (used by the credentials submenu). */
  private async configureLangfuseInteractive(): Promise<void> {
    display.blank();
    display.print(pc.bold(pc.cyan('Langfuse Tracing Configuration')));
    display.print(pc.dim('Langfuse provides observability for your threat modeling workflows.'));
    display.print(pc.dim('Get your API keys from: https://cloud.langfuse.com'));
    display.blank();

    const enable = await confirm({ message: 'Enable Langfuse tracing?', default: true });
    if (!enable) {
      this.env.setValue('LANGFUSE_ENABLED', 'false');
      display.blank();
      display.print(pc.dim('Langfuse tracing disabled'));
      return;
    }
    const currentPublic = this.env.getValue('LANGFUSE_PUBLIC_KEY') ?? '';
    const publicKey = await input({
      message: 'Langfuse Public Key (pk-lf-...):',
      default: currentPublic && currentPublic !== 'pk-lf-your-public-key' ? currentPublic : '',
    });
    const secretKey = await password({ message: 'Langfuse Secret Key (sk-lf-...):' });
    const host = await input({
      message: 'Langfuse Host (optional, for self-hosted):',
      default: this.env.getValue('LANGFUSE_HOST') ?? 'https://cloud.langfuse.com',
    });
    this.env.setValue('LANGFUSE_ENABLED', 'true');
    this.env.setValue('LANGFUSE_PUBLIC_KEY', publicKey);
    this.env.setValue('LANGFUSE_SECRET_KEY', secretKey);
    if (host) this.env.setValue('LANGFUSE_HOST', host);
    display.blank();
    display.print(`${pc.green('✓')} Langfuse enabled`);
  }

  /** Model-settings editor (delegates to ConfigManager.editInteractive). */
  async configureModelSettings(): Promise<boolean> {
    if (!existsSync(this.cfgMgr.userConfigFile)) await this.cfgMgr.initUserConfig();
    await this.cfgMgr.editInteractive();
    display.blank();
    display.print(`${pc.green('✓')} Model settings updated!`);
    display.print(pc.dim('Restart ThreatForest to use new model configuration'));
    display.blank();
    return true;
  }
}

/** Re-read the on-disk config and reset the engine's cached singleton. */
export function reloadConfig(): void {
  config.reset();
}

/** Read raw config.yaml (used by display of active provider). */
export function readConfigYaml(): Record<string, unknown> {
  const file = new ConfigManager().userConfigFile;
  if (!existsSync(file)) return defaultConfigData();
  return (parseYaml(readFileSync(file, 'utf8')) as Record<string, unknown>) ?? {};
}
