/**
 * Config CRUD — TS port of
 * `src/threatforest/modules/utils/config_manager.py`.
 *
 * Reads/writes `.threatforest/config.yaml`. The Python ConfigManager copies a
 * bundled `config.yaml`; the TS tree ships no such file, so init/migration build
 * a canonical default (the four SDK-native providers + the framework registry)
 * via `defaultConfigData()`. The resolution path matches the engine Config
 * (cwd-first), so the `threatforest run` wizard and `config show` agree.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { FRAMEWORKS } from '@threatforest/engine';
import { DEFAULT_MODELS } from './model-configs.js';
import * as display from './display.js';
import pc from 'picocolors';

/** The canonical default config (replaces copying a bundled config.yaml). */
export function defaultConfigData(): Record<string, unknown> {
  const frameworks: Record<string, unknown> = {};
  const descriptions: Record<string, string> = {
    attack: '835 techniques — cloud, network, endpoint',
    atlas: 'AI/ML adversarial threats',
    wiz: 'cloud threat landscape',
  };
  for (const [key, fw] of Object.entries(FRAMEWORKS)) {
    frameworks[key] = {
      name: fw.name,
      description: descriptions[key] ?? '',
      stix_bundle: fw.stix_bundle,
      source_name: fw.source_name,
      kill_chain_name: fw.kill_chain_name,
    };
  }
  return {
    bedrock: { model_id: DEFAULT_MODELS.bedrock },
    embeddings: { model: 'basel/ATTACK-BERT', ttc_threshold: 0.3 },
    frameworks,
  };
}

export class ConfigManager {
  readonly userConfigDir: string;
  readonly userConfigFile: string;

  constructor(rootDir: string = process.cwd()) {
    this.userConfigDir = join(rootDir, '.threatforest');
    this.userConfigFile = join(this.userConfigDir, 'config.yaml');
  }

  private read(): Record<string, unknown> {
    return (parseYaml(readFileSync(this.userConfigFile, 'utf8')) as Record<string, unknown>) ?? {};
  }

  private write(data: Record<string, unknown>): void {
    mkdirSync(this.userConfigDir, { recursive: true });
    writeFileSync(this.userConfigFile, stringifyYaml(data));
  }

  /** No-op migration hook (frameworks come from the canonical registry). */
  migrateConfig(): boolean {
    return false;
  }

  /** `config init` — write the default config (prompting before overwrite). */
  async initUserConfig(force = false): Promise<boolean> {
    if (existsSync(this.userConfigFile) && !force) {
      display.print(pc.yellow(`Config already exists: ${this.userConfigFile}`));
      const { confirm } = await import('@inquirer/prompts');
      const overwrite = await confirm({ message: 'Overwrite existing config?', default: false });
      if (!overwrite) return false;
    }
    this.write(defaultConfigData());
    display.blank();
    display.print(`${pc.green('✓')} Created config: ${pc.cyan(this.userConfigFile)}`);
    display.blank();
    display.print(pc.dim('Edit this file to customize your ThreatForest settings.'));
    display.blank();
    return true;
  }

  /** `config show` — render the active provider + key settings. */
  showConfig(): void {
    const data = existsSync(this.userConfigFile) ? this.read() : defaultConfigData();
    const configSource = existsSync(this.userConfigFile)
      ? '.threatforest/config.yaml (project config)'
      : 'Bundled default';

    const { provider, modelId } = detectProvider(data);
    const embeddings = (data.embeddings ?? {}) as Record<string, unknown>;
    const embeddingsModel = (embeddings.model as string) ?? 'basel/ATTACK-BERT';
    const ttc = (embeddings.ttc_threshold as number) ?? 0.3;

    const rows: [string, string][] = [
      ['Config Source', configSource],
      ['Model Provider', provider ?? 'Not configured'],
      ['Model ID', modelId ?? 'None'],
      ['Embeddings Model', embeddingsModel],
      ['TTP Threshold', String(ttc)],
    ];
    const keyWidth = Math.max(...rows.map(([k]) => k.length));
    display.blank();
    display.print(pc.bold(pc.cyan('ThreatForest Configuration')));
    for (const [k, v] of rows) display.print(`  ${pc.cyan(k.padEnd(keyWidth))}  ${pc.green(v)}`);
    display.blank();
  }

  /** `config edit` — interactive provider/model picker. */
  async editInteractive(): Promise<void> {
    if (!existsSync(this.userConfigFile)) {
      display.print(pc.yellow('No user config found. Initializing...'));
      await this.initUserConfig();
    }
    const data = this.read();
    display.blank();
    display.print(pc.bold(pc.cyan('Interactive Configuration Editor')));
    display.blank();

    const { select, input } = await import('@inquirer/prompts');
    const providerChoice = await select({
      message: 'Select AI Provider:',
      choices: [
        { name: 'AWS Bedrock', value: 'AWS Bedrock' },
        { name: 'Anthropic (Experimental)', value: 'Anthropic' },
        { name: 'OpenAI (Experimental)', value: 'OpenAI' },
        { name: 'Google Gemini (Experimental)', value: 'Google Gemini' },
        { name: 'Ollama (Experimental)', value: 'Ollama' },
        { name: 'Keep current', value: 'Keep current' },
      ],
    });

    if (providerChoice !== 'Keep current') {
      display.blank();
      display.print(`${pc.green('✓')} Selected: ${providerChoice}`);
      const { BEDROCK_MODELS, ANTHROPIC_MODELS, OPENAI_MODELS, GEMINI_MODELS } = await import(
        './model-configs.js'
      );

      const pickModel = async (
        blockKey: string,
        models: string[],
        allowOther: boolean,
      ): Promise<void> => {
        const block = (data[blockKey] ?? {}) as Record<string, unknown>;
        const current = (block.model_id as string) ?? DEFAULT_MODELS[blockKey];
        const choices = [
          ...models.map((m) => ({ name: m, value: m })),
          ...(allowOther ? [{ name: 'Other (enter custom model ID)', value: '__other__' }] : []),
          { name: 'Keep current', value: '__keep__' },
        ];
        let choice = await select({ message: `Select model (current: ${current}):`, choices });
        if (choice === '__keep__') return;
        if (choice === '__other__') {
          choice = await input({ message: 'Enter custom model ID:', default: '' });
        }
        data[blockKey] = { ...block, model_id: choice };
        display.print(`${pc.green('✓')} Model: ${choice}`);
      };

      if (providerChoice === 'AWS Bedrock') await pickModel('bedrock', BEDROCK_MODELS, true);
      else if (providerChoice === 'Anthropic') await pickModel('anthropic', ANTHROPIC_MODELS, false);
      else if (providerChoice === 'OpenAI') await pickModel('openai', OPENAI_MODELS, false);
      else if (providerChoice === 'Google Gemini') await pickModel('gemini', GEMINI_MODELS, false);
      else if (providerChoice === 'Ollama') {
        const block = (data.ollama ?? {}) as Record<string, unknown>;
        const current = (block.model_id as string) ?? DEFAULT_MODELS.ollama;
        const modelId = await input({ message: `Enter Ollama Model ID (current: ${current}):`, default: current });
        data.ollama = { ...block, model_id: modelId };
        display.print(`${pc.green('✓')} Model: ${modelId}`);
      }
    }

    this.write(data);
    display.blank();
    display.print(`${pc.green('✓')} Config saved: ${pc.cyan(this.userConfigFile)}`);
    display.blank();
  }

  /** `config set KEY VALUE` — dot-notation set. */
  async setValue(key: string, value: string): Promise<void> {
    if (!existsSync(this.userConfigFile)) {
      display.print(pc.yellow('No user config found. Initializing...'));
      await this.initUserConfig();
    }
    const data = this.read();
    const keys = key.split('.');
    let current: Record<string, unknown> = data;
    for (const k of keys.slice(0, -1)) {
      if (typeof current[k] !== 'object' || current[k] === null) current[k] = {};
      current = current[k] as Record<string, unknown>;
    }
    current[keys[keys.length - 1]!] = value;
    this.write(data);
    display.print(`${pc.green('✓')} Set ${pc.cyan(key)} = ${pc.yellow(value)}`);
  }

  /** `config path` — the active config file. */
  getConfigPath(): string {
    return this.userConfigFile;
  }
}

/** First-configured-block-wins provider detection (mirrors cli.py + config_manager.py). */
export function detectProvider(data: Record<string, unknown>): {
  provider: string | null;
  modelId: string | null;
} {
  const block = (k: string): Record<string, unknown> | null => {
    const v = data[k];
    return v && typeof v === 'object' ? (v as Record<string, unknown>) : null;
  };
  const order: [string, string, string][] = [
    ['bedrock', 'AWS Bedrock', 'model_id'],
    ['anthropic', 'Anthropic', 'model_id'],
    ['openai', 'OpenAI', 'model_id'],
    ['gemini', 'Google Gemini', 'model_id'],
    ['ollama', 'Ollama', 'model_id'],
    ['sagemaker', 'AWS SageMaker', 'endpoint_name'],
  ];
  for (const [key, name, idField] of order) {
    const b = block(key);
    if (b && b[idField]) return { provider: name, modelId: String(b[idField]) };
  }
  return { provider: null, modelId: null };
}
