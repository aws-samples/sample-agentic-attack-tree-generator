/**
 * Terminal display helpers — picocolors port of the Rich-based CLI output in
 * `src/threatforest/modules/cli/display.py` (welcome banner, config table,
 * panels, step headers, summaries). We don't reproduce Rich's box-drawing
 * pixel-for-pixel; instead we render readable, coloured equivalents.
 */
import pc from 'picocolors';

/** Print a blank line (matches the frequent `console.print()` in the Python). */
export function blank(): void {
  process.stdout.write('\n');
}

export function print(line = ''): void {
  process.stdout.write(`${line}\n`);
}

/** A simple bordered panel, the analog of rich.panel.Panel. */
export function panel(body: string, opts: { title?: string; color?: (s: string) => string } = {}): void {
  const color = opts.color ?? pc.cyan;
  const lines = body.split('\n');
  const width = Math.max(
    opts.title ? opts.title.length + 4 : 0,
    ...lines.map((l) => stripWidth(l)),
  );
  const top = opts.title
    ? `╭─ ${pc.bold(opts.title)} ${'─'.repeat(Math.max(0, width - opts.title.length - 2))}╮`
    : `╭${'─'.repeat(width + 2)}╮`;
  print(color(top));
  for (const l of lines) {
    print(`${color('│')} ${l}${' '.repeat(Math.max(0, width - stripWidth(l)))} ${color('│')}`);
  }
  print(color(`╰${'─'.repeat(width + 2)}╯`));
}

/** Length of a string ignoring ANSI escape codes (for panel alignment). */
function stripWidth(s: string): number {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\[[0-9;]*m/g, '').length;
}

export function showWelcome(): void {
  blank();
  panel(
    `${pc.bold(pc.blue('🌳 ThreatForest'))}\n${pc.dim('AI-Driven Threat Modeling & Attack Tree Generation')}`,
    { title: 'Welcome', color: pc.blue },
  );
  blank();
}

export interface ConfigDisplay {
  model_provider: string | null;
  model_id: string | null;
  embeddings_model: string;
  ttc_threshold: number;
}

export function showConfig(cfg: ConfigDisplay): void {
  blank();
  const rows: [string, string][] = [
    ['Model Provider', cfg.model_provider ?? 'Not configured'],
    ['Model ID', cfg.model_id ?? 'None'],
    ['Embeddings Model', cfg.embeddings_model],
    ['TTP Threshold', String(cfg.ttc_threshold)],
  ];
  const keyWidth = Math.max(...rows.map(([k]) => k.length));
  print(pc.bold(pc.cyan('ThreatForest Configuration')));
  for (const [k, v] of rows) {
    print(`  ${pc.cyan(k.padEnd(keyWidth))}  ${pc.green(v)}`);
  }
  blank();
}

export function showInfo(message: string): void {
  print(`${pc.cyan('ℹ')} ${message}`);
}

export function showError(
  message: string,
  title = 'Error',
  suggestions: string[] = [],
): void {
  blank();
  let body = `${pc.red(message)}`;
  if (suggestions.length) {
    body += '\n\n' + pc.dim('Suggestions:');
    for (const s of suggestions) body += `\n  ${pc.dim('•')} ${s}`;
  }
  panel(body, { title, color: pc.red });
  blank();
}

export function showStepHeader(current: number, total: number, title: string, subtitle?: string): void {
  blank();
  let bar = '';
  for (let i = 1; i <= total; i += 1) {
    if (i < current) bar += pc.green('● ');
    else if (i === current) bar += pc.blue('● ');
    else bar += pc.dim('○ ');
  }
  let body = `${bar}\n\n${pc.bold(pc.blue(`Step ${current}/${total}:`))} ${pc.bold(title)}`;
  if (subtitle) body += `\n${pc.dim(subtitle)}`;
  panel(body, { color: pc.blue });
  blank();
}

export function showReviewConfig(opts: {
  mode: string;
  project_path: string;
  threat_model?: string | null;
}): void {
  blank();
  const rows: [string, string][] = [
    ['Mode', opts.mode],
    ['Project Path', opts.project_path],
    ['Threat Statements', opts.threat_model ?? 'Auto-generate'],
  ];
  const keyWidth = Math.max(...rows.map(([k]) => k.length));
  const body = rows.map(([k, v]) => `${pc.cyan(k.padEnd(keyWidth))}  ${pc.green(v)}`).join('\n');
  panel(body, { title: 'Review Configuration', color: pc.cyan });
  blank();
}

export function showSummary(summary: Record<string, unknown>): void {
  if (Object.keys(summary).length === 0) return;
  blank();
  const rows = Object.entries(summary).map(([k, v]) => {
    const label = k
      .split('_')
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
    return [label, String(v)] as [string, string];
  });
  const keyWidth = Math.max(...rows.map(([k]) => k.length));
  const body = rows.map(([k, v]) => `${pc.cyan(k.padEnd(keyWidth))}  ${pc.green(v)}`).join('\n');
  panel(body, { title: 'Summary', color: pc.green });
  blank();
}
