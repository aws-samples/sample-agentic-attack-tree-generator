/**
 * .env management — TS port of
 * `src/threatforest/modules/utils/env_manager.py`.
 *
 * Reads/writes `.threatforest/.env` (rooted at cwd, matching the engine Config's
 * cwd-first resolution). Values are also mirrored into `process.env` on write so
 * subsequent reads in the same process reflect the change immediately.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export class EnvManager {
  readonly envFile: string;

  constructor(rootDir: string = process.cwd()) {
    this.envFile = join(rootDir, '.threatforest', '.env');
    mkdirSync(dirname(this.envFile), { recursive: true });
  }

  getValue(key: string): string | null {
    // Environment first (mirrors os.getenv precedence).
    const fromEnv = process.env[key];
    if (fromEnv) return fromEnv;

    if (existsSync(this.envFile)) {
      for (const raw of readFileSync(this.envFile, 'utf8').split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#') || !line.includes('=')) continue;
        const idx = line.indexOf('=');
        const envKey = line.slice(0, idx).trim();
        if (envKey === key) return line.slice(idx + 1).trim();
      }
    }
    return null;
  }

  setValue(key: string, value: string): void {
    process.env[key] = value;

    let lines: string[] = [];
    let found = false;
    if (existsSync(this.envFile)) {
      lines = readFileSync(this.envFile, 'utf8').split('\n');
      lines = lines.map((line) => {
        if (line.trim().startsWith(`${key}=`)) {
          found = true;
          return `${key}=${value}`;
        }
        return line;
      });
      // Drop a trailing empty element produced by split on a file ending in \n.
      if (lines.length && lines[lines.length - 1] === '') lines.pop();
    }
    if (!found) lines.push(`${key}=${value}`);
    writeFileSync(this.envFile, lines.join('\n') + '\n');
  }

  ensureExists(): void {
    if (!existsSync(this.envFile)) writeFileSync(this.envFile, '');
  }
}
