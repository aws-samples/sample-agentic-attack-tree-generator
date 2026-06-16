/**
 * `threatforest config langfuse` — TS port of the click `config_langfuse`
 * command in cli.py. Manages LANGFUSE_* env credentials in .threatforest/.env.
 *
 * Parity caveats (see file caveats in the summary): the Python command also runs
 * a live connection auth_check and registers Langfuse score-config definitions
 * via the `langfuse` SDK + ScoreConfigRegistry. Those depend on the Python-only
 * tracing modules and the langfuse Python package; here --test / --register-scores
 * / --sync-scores print a clear "not available in the TS CLI" notice rather than
 * silently no-op'ing. Credential management is fully faithful.
 */
import { confirm, input, password } from '@inquirer/prompts';
import pc from 'picocolors';
import { EnvManager } from './env-manager.js';
import * as display from './display.js';

export interface LangfuseOpts {
  enable?: boolean; // --enable / --disable -> true/false; undefined when neither
  publicKey?: string;
  secretKey?: string;
  host?: string;
  test?: boolean;
  registerScores?: boolean;
  syncScores?: boolean;
}

export async function runLangfuseCommand(opts: LangfuseOpts): Promise<void> {
  const env = new EnvManager();
  env.ensureExists();

  let { enable, publicKey, secretKey, host, test } = opts;
  const { registerScores, syncScores } = opts;

  const noOptions =
    enable === undefined &&
    publicKey === undefined &&
    secretKey === undefined &&
    host === undefined &&
    !test;

  // Interactive setup when no flags are given.
  if (noOptions) {
    display.blank();
    display.print(pc.bold(pc.cyan('Langfuse Tracing Configuration')));
    display.print(pc.dim('Langfuse provides observability for your threat modeling workflows.'));
    display.print(pc.dim('Get your API keys from: https://cloud.langfuse.com'));
    display.blank();

    const currentEnabled = env.getValue('LANGFUSE_ENABLED') === 'true';
    const currentPublic = env.getValue('LANGFUSE_PUBLIC_KEY') ?? '';
    const currentHost = env.getValue('LANGFUSE_HOST') ?? 'https://cloud.langfuse.com';

    if (currentEnabled && currentPublic) {
      display.print(`${pc.green('✓')} Currently enabled with key: ${currentPublic.slice(0, 20)}...`);
    } else {
      display.print(pc.dim('○ Currently not configured'));
    }
    display.blank();

    const enableChoice = await confirm({ message: 'Enable Langfuse tracing?', default: true });
    if (!enableChoice) {
      env.setValue('LANGFUSE_ENABLED', 'false');
      display.blank();
      display.print(pc.dim('Langfuse tracing disabled'));
      display.blank();
      return;
    }

    publicKey = await input({
      message: 'Langfuse Public Key (pk-lf-...):',
      default: currentPublic && !currentPublic.includes('your-public-key') ? currentPublic : '',
    });
    secretKey = await password({ message: 'Langfuse Secret Key (sk-lf-...):' });
    host = await input({ message: 'Langfuse Host (optional):', default: currentHost });

    env.setValue('LANGFUSE_ENABLED', 'true');
    env.setValue('LANGFUSE_PUBLIC_KEY', publicKey);
    env.setValue('LANGFUSE_SECRET_KEY', secretKey);
    if (host) env.setValue('LANGFUSE_HOST', host);

    display.blank();
    display.print(`${pc.green('✓')} Langfuse configured successfully!`);
    test = true; // Auto-test after interactive setup (matches Python).
  } else if (enable === false) {
    env.setValue('LANGFUSE_ENABLED', 'false');
    display.blank();
    display.print(`${pc.green('✓')} Langfuse tracing disabled`);
    display.blank();
    return;
  } else {
    if (enable === true) env.setValue('LANGFUSE_ENABLED', 'true');
    if (publicKey) {
      env.setValue('LANGFUSE_PUBLIC_KEY', publicKey);
      display.print(`${pc.green('✓')} Public key configured`);
    }
    if (secretKey) {
      env.setValue('LANGFUSE_SECRET_KEY', secretKey);
      display.print(`${pc.green('✓')} Secret key configured`);
    }
    if (host) {
      env.setValue('LANGFUSE_HOST', host);
      display.print(`${pc.green('✓')} Host configured: ${host}`);
    }
    if (enable === true) display.print(`${pc.green('✓')} Langfuse tracing enabled`);
  }

  if (test) {
    display.blank();
    display.print(pc.cyan('Testing Langfuse connection...'));
    const testPublic = publicKey ?? env.getValue('LANGFUSE_PUBLIC_KEY');
    const testSecret = secretKey ?? env.getValue('LANGFUSE_SECRET_KEY');
    const testHost = host ?? env.getValue('LANGFUSE_HOST') ?? 'https://cloud.langfuse.com';
    if (!testPublic || !testSecret) {
      display.print(`${pc.red('Error:')} Missing public key or secret key`);
      display.print(pc.dim('Configure credentials first: threatforest config langfuse'));
      display.blank();
      return;
    }
    // STUB: live auth_check + score-config registration is Python-only.
    display.print(
      pc.yellow(
        '⚠️  Live connection test and score-config registration are not available in the TS CLI ' +
          '(they require the Python langfuse SDK + tracing modules). Credentials saved; the engine ' +
          'reads LANGFUSE_* from .env at run time.',
      ),
    );
    display.print(pc.dim(`Host: ${testHost}  Public Key: ${testPublic.slice(0, 20)}...`));
  }

  if (registerScores || syncScores) {
    display.blank();
    display.print(
      pc.yellow(
        '⚠️  --register-scores / --sync-scores are not available in the TS CLI ' +
          '(Python-only ScoreConfigRegistry). No changes made.',
      ),
    );
  }

  display.blank();
}
