#!/usr/bin/env node
/**
 * @threatforest/cli — the `threatforest` entry point. TS port of
 * `src/threatforest/cli.py` (click) using commander.
 *
 * Command structure (mirrors the Python click CLI):
 *   threatforest                       launch the web console (default)
 *   threatforest --tui                 run the interactive wizard instead
 *   threatforest run [opts]            run the workflow (wizard if no --project-path)
 *   threatforest status                show workflow status (stub, as in Python)
 *   threatforest config init|show|edit|set|path|langfuse
 *   threatforest export traces [opts]  (stub — Python-only Langfuse exporter)
 *   threatforest help                  command reference
 *
 * Bounded gaps vs the Python CLI are documented in the WS-5 summary; each stubbed
 * path prints a clear notice rather than silently no-op'ing.
 */
import { Command, Option } from 'commander';
import pc from 'picocolors';

import { config } from '@threatforest/engine';
import * as display from './display.js';
import { launchServer } from './server-launch.js';
import { ConfigManager, detectProvider } from './config-manager.js';
import { CLIWizard, reloadConfig, readConfigYaml, type SelectedMode } from './wizard.js';
import { runFullWorkflow } from './run-workflow.js';
import { runLangfuseCommand } from './langfuse-cmd.js';

/** Build the config-display object from the engine Config (port of cli.py logic). */
function buildConfigDisplay(): display.ConfigDisplay {
  const { provider, modelId } = detectProvider(readConfigYaml());
  let embeddingsModel = 'basel/ATTACK-BERT';
  let ttc = 0.3;
  try {
    embeddingsModel = config.embeddingsModel;
    ttc = config.ttcThreshold;
  } catch {
    // No config file yet — defaults above stand.
  }
  return { model_provider: provider, model_id: modelId, embeddings_model: embeddingsModel, ttc_threshold: ttc };
}

interface RunOptions {
  projectPath?: string;
  threatModel?: string;
  mode: 'full' | 'enrich' | 'mitigate';
  inputDir?: string;
  outputDir?: string;
  frameworks?: string;
}

async function runCommand(opts: RunOptions): Promise<void> {
  const wizard = new CLIWizard();

  // Parse --frameworks (comma-separated) into a list, or null for all.
  let selectedFrameworks: string[] | null = null;
  if (opts.frameworks) {
    selectedFrameworks = opts.frameworks
      .split(',')
      .map((f) => f.trim())
      .filter(Boolean);
  }

  let projectPath = opts.projectPath;

  try {
    await wizard.checkAndInitConfig();
    reloadConfig();

    display.showWelcome();
    display.showConfig(buildConfigDisplay());

    let result: { status: string; output_dir?: string; error?: string };

    if (projectPath === undefined) {
      // Interactive mode — loop to allow returning to the menu after config changes.
      for (;;) {
        const selectedMode: SelectedMode = await wizard.selectMode();

        if (selectedMode === 'exit') {
          display.blank();
          display.print(pc.cyan('👋 Thanks for using ThreatForest!'));
          display.blank();
          process.exit(0);
        }
        if (selectedMode === 'credentials') {
          await wizard.updateCredentials();
          reloadConfig();
          display.showConfig(buildConfigDisplay());
          continue;
        }
        if (selectedMode === 'model_settings') {
          await wizard.configureModelSettings();
          reloadConfig();
          display.showConfig(buildConfigDisplay());
          continue;
        }
        wizard.showModeInfo(selectedMode);
        break;
      }

      projectPath = await wizard.getProjectPath();
      if (selectedFrameworks === null) selectedFrameworks = await wizard.selectFrameworks();
      const [, threatFilePath] = await wizard.askThreatStatementPreference();

      display.showReviewConfig({ mode: 'full', project_path: projectPath, threat_model: threatFilePath });

      if (!(await wizard.confirmContinue('Ready to start analysis?'))) {
        display.showInfo('Analysis cancelled by user');
        process.exit(0);
      }

      display.showStepHeader(5, 5, 'Executing Analysis', 'This may take several minutes...');
      result = await runFullWorkflow(projectPath, selectedFrameworks);
    } else {
      // Non-interactive mode.
      if (opts.mode === 'full') {
        display.showInfo(`Running full workflow for: ${projectPath}`);
        result = await runFullWorkflow(projectPath, selectedFrameworks);
      } else if (opts.mode === 'enrich' || opts.mode === 'mitigate') {
        // STUB: the TS engine exposes only the full graph (runGraph). The
        // standalone enrich/mitigate runners (runner.run_enrichment /
        // run_mitigation) are not ported — see WS-5 caveats.
        if (!opts.inputDir || !opts.outputDir) {
          display.showError(
            `${opts.mode} mode requires --input-dir and --output-dir`,
            'Missing arguments',
            ['Use --input-dir to specify input directory', 'Use --output-dir to specify output directory'],
          );
          process.exit(1);
        }
        display.showError(
          `'${opts.mode}' mode is not available in the TS CLI.`,
          'Unsupported mode',
          [
            'The TS engine runs the full pipeline only (threatforest run --mode full).',
            'Standalone enrich/mitigate stages were not ported in this migration.',
          ],
        );
        process.exit(1);
        return;
      } else {
        display.showError(`Unknown mode: ${opts.mode}`, 'Invalid mode');
        process.exit(1);
        return;
      }
    }

    // Display results — engine returns { status: 'success' | 'failed', output_dir, error? }.
    const isSuccessful = result.status === 'success' || (result as { success?: boolean }).success === true;

    if (isSuccessful) {
      display.showSummary({ ...(result.output_dir ? { output_dir: result.output_dir } : {}) });
      const outputDirectory = result.output_dir;
      if (outputDirectory) {
        display.blank();
        display.print(`📁 ${pc.bold(pc.cyan('Output Directory:'))} ${outputDirectory}`);
        display.blank();
      } else {
        display.blank();
        display.print(pc.yellow('⚠️  Output directory information not available'));
        display.blank();
      }
    } else {
      display.showError(result.error ?? 'Unknown error', 'Workflow Failed', [
        'Check the logs for detailed error information',
        'Verify all configuration settings in config.yaml',
        'Ensure AWS credentials are properly configured',
      ]);
      process.exit(1);
    }
  } catch (err) {
    if ((err as { name?: string }).name === 'ExitPromptError') {
      // Ctrl-C at an @inquirer prompt.
      display.blank();
      display.print(pc.yellow('👋 ThreatForest interrupted by user'));
      process.exit(0);
    }
    display.showError((err as Error).message, 'Unexpected Error', [
      'Check logs in the run output directory',
      'Verify project structure and permissions',
      'Run with --help for usage information',
    ]);
    display.blank();
    display.print(pc.dim('Stack trace:'));
    display.print(pc.dim((err as Error).stack ?? ''));
    process.exit(1);
  }
}

function printHelp(): void {
  display.print(`
${pc.bold(pc.cyan('ThreatForest CLI Commands:'))}

  ${pc.cyan('run')}              Run threat modeling workflow (interactive or with options)
  ${pc.cyan('config init')}      Initialize user configuration (./.threatforest/config.yaml)
  ${pc.cyan('config show')}      Show current configuration
  ${pc.cyan('config edit')}      Edit configuration interactively
  ${pc.cyan('config set')}       Set a specific config value
  ${pc.cyan('config path')}      Show path to active config file
  ${pc.cyan('config langfuse')}  Configure Langfuse tracing credentials
  ${pc.cyan('export traces')}    Export traces from Langfuse to Langfuse Datasets
  ${pc.cyan('status')}           Show current workflow status

${pc.bold('Examples:')}

  # Launch the web console (default)
  threatforest

  # Interactive wizard
  threatforest --tui

  # Initialize user config
  threatforest config init

  # View configuration
  threatforest config show

  # Set specific value
  threatforest config set bedrock.model_id claude-sonnet-4

  # Configure Langfuse (interactive)
  threatforest config langfuse

  # Full workflow with project path
  threatforest run --project-path /path/to/project

For more information, visit: https://github.com/aws-samples/sample-agentic-attack-tree-generator
`);
}

function buildProgram(): Command {
  const program = new Command();
  program
    .name('threatforest')
    .description('ThreatForest - AI-Driven Threat Modeling')
    // Default (no subcommand) options mirror the click group options.
    .option('--tui', 'Run in interactive terminal mode', false)
    .option('--host <host>', 'Host for web console server', '127.0.0.1')
    .option('--port <port>', 'Port for web console server', '8000')
    .allowExcessArguments(false);

  // Default action: launch web console, or the wizard with --tui.
  program.action(async (opts: { tui: boolean; host: string; port: string }) => {
    if (opts.tui) {
      await runCommand({ mode: 'full' });
      return;
    }
    await launchServer(opts.host, Number(opts.port));
  });

  // --- run ---
  program
    .command('run')
    .description('Run ThreatForest workflow')
    .option('-p, --project-path <path>', 'Project directory path')
    .option('-t, --threat-model <path>', 'Threat model file path (optional)')
    .addOption(
      new Option('-m, --mode <mode>', 'Workflow mode').choices(['full', 'enrich', 'mitigate']).default('full'),
    )
    .option('-i, --input-dir <dir>', 'Input directory (for enrich/mitigate modes)')
    .option('-o, --output-dir <dir>', 'Output directory (for enrich/mitigate modes)')
    .option('-f, --frameworks <list>', 'Comma-separated frameworks to map to (e.g. attack,atlas). Default: all')
    .action(async (opts: RunOptions) => {
      await runCommand(opts);
    });

  // --- status ---
  program
    .command('status')
    .description('Show current workflow status')
    .action(() => {
      display.print(pc.yellow('Status command not yet implemented'));
    });

  // --- config (group) ---
  const cfg = program.command('config').description('Manage ThreatForest configuration');

  cfg
    .command('init')
    .description('Initialize user configuration file')
    .option('-f, --force', 'Overwrite existing config', false)
    .action(async (opts: { force: boolean }) => {
      await new ConfigManager().initUserConfig(opts.force);
    });

  cfg
    .command('show')
    .description('Show current configuration')
    .action(() => {
      new ConfigManager().showConfig();
    });

  cfg
    .command('edit')
    .description('Edit configuration interactively')
    .action(async () => {
      await new ConfigManager().editInteractive();
    });

  cfg
    .command('set')
    .description('Set a configuration value (e.g., threatforest config set bedrock.model_id claude-sonnet-4)')
    .argument('<key>')
    .argument('<value>')
    .action(async (key: string, value: string) => {
      await new ConfigManager().setValue(key, value);
    });

  cfg
    .command('path')
    .description('Show path to active config file')
    .action(() => {
      display.blank();
      display.print(`${pc.cyan('Config file:')} ${new ConfigManager().getConfigPath()}`);
      display.blank();
    });

  cfg
    .command('langfuse')
    .description('Configure Langfuse tracing credentials')
    .addOption(new Option('--enable', 'Enable Langfuse tracing'))
    .addOption(new Option('--disable', 'Disable Langfuse tracing'))
    .option('-p, --public-key <key>', 'Langfuse public key (pk-lf-...)')
    .option('-s, --secret-key <key>', 'Langfuse secret key (sk-lf-...)')
    .option('-h, --host <host>', 'Langfuse host (default: https://cloud.langfuse.com)')
    .option('--test', 'Test the connection after configuring')
    .option('--register-scores', 'Register score definitions with Langfuse')
    .option('--sync-scores', 'Sync local registry with existing Langfuse score configs')
    .action(
      async (opts: {
        enable?: boolean;
        disable?: boolean;
        publicKey?: string;
        secretKey?: string;
        host?: string;
        test?: boolean;
        registerScores?: boolean;
        syncScores?: boolean;
      }) => {
        // Map --enable/--disable to a tri-state (true / false / undefined).
        let enable: boolean | undefined;
        if (opts.enable) enable = true;
        else if (opts.disable) enable = false;
        await runLangfuseCommand({
          enable,
          publicKey: opts.publicKey,
          secretKey: opts.secretKey,
          host: opts.host,
          test: opts.test,
          registerScores: opts.registerScores,
          syncScores: opts.syncScores,
        });
      },
    );

  // --- export (group) ---
  const exp = program.command('export').description('Export traces from Langfuse to Langfuse Datasets');
  exp
    .command('traces')
    .description('Export traces from Langfuse to a Langfuse Dataset')
    .addOption(
      new Option('-t, --trace-type <type>').choices(['threat_statement', 'attack_tree', 'ttp_matching']),
    )
    .addOption(new Option('-s, --status <status>').choices(['pending_review', 'reviewed']))
    .option('--start-date <date>', 'Filter by start date (ISO format)')
    .option('--end-date <date>', 'Filter by end date (ISO format)')
    .option('--ground-truth-only', 'Only export ground truth candidates', false)
    .requiredOption('-d, --dataset-name <name>', 'Name of the Langfuse Dataset to export to')
    .option('--dataset-description <desc>', 'Description for the dataset')
    .option('--dry-run', 'Show what would be exported without exporting', false)
    .action(() => {
      // STUB: the Langfuse dataset exporter (LangfuseDatasetExporter) is
      // Python-only; not ported in this migration. See WS-5 caveats.
      display.showError(
        'export traces is not available in the TS CLI.',
        'Unsupported command',
        [
          'The Langfuse dataset exporter is implemented only in the Python package.',
          'Use the Python CLI for trace export, or run exports directly in Langfuse.',
        ],
      );
      process.exit(1);
    });

  // --- help ---
  program
    .command('help')
    .description('Show help information')
    .action(() => {
      printHelp();
    });

  return program;
}

async function main(): Promise<void> {
  const program = buildProgram();
  await program.parseAsync(process.argv);
}

main().catch((err) => {
  if ((err as { name?: string }).name === 'ExitPromptError') {
    display.blank();
    display.print(pc.yellow('👋 ThreatForest interrupted by user'));
    process.exit(0);
  }
  display.showError((err as Error).message, 'Fatal Error');
  process.exit(1);
});
