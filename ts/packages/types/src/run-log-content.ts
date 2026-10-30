import type { RunLogContent } from './hosted.js';

export const MAX_LOG_CONTENT_CHARACTERS = 12_000;
const SECRET_FIELD = /^(authorization|cookie|setcookie|password|passwd|secret|clientsecret|credentials?|apikey|accesskeyid|secretaccesskey|sessiontoken|accesstoken|refreshtoken|idtoken|token|signature|reasoningsignature|redactedcontent|systemprompt|systeminstructions)$/i;

export function redactLogText(value: string): string {
  return value
    .replace(/\/(?:private\/)?tmp\/threatforest\/owners\/[^/]+\/applications\/[^/]+\/runs\/[^/]+\//g, '')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[redacted-access-key]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted-token]')
    .replace(/((?:["']?)(?:password|passwd|api[_-]?key|client[_-]?secret|secret[_-]?access[_-]?key|aws_secret_access_key|access[_-]?token|refresh[_-]?token|session[_-]?token|authorization)(?:["']?)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi, '$1[redacted]');
}

export function sanitizeLogValue(value: unknown, depth = 0, onOmission?: () => void): unknown {
  if (depth > 12) {
    onOmission?.();
    return '[nested content omitted]';
  }
  if (typeof value === 'string') return redactLogText(value);
  if (Array.isArray(value)) {
    if (value.length > 100) onOmission?.();
    return value.slice(0, 100).map((item) => sanitizeLogValue(item, depth + 1, onOmission));
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length > 100) onOmission?.();
    return Object.fromEntries(entries.slice(0, 100).map(([key, item]) => [
      key,
      SECRET_FIELD.test(key.replace(/[_\s.-]/g, '')) ? '[redacted]' : sanitizeLogValue(item, depth + 1, onOmission),
    ]));
  }
  return value;
}

export function parseLogJson(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { return value; }
}

export function logContent(kind: RunLogContent['kind'], value: unknown): RunLogContent {
  let omitted = false;
  const safe = sanitizeLogValue(parseLogJson(value), 0, () => { omitted = true; });
  const text = typeof safe === 'string' ? safe : JSON.stringify(safe, null, 2) ?? '';
  return { kind, text: text.slice(0, MAX_LOG_CONTENT_CHARACTERS), truncated: omitted || text.length > MAX_LOG_CONTENT_CHARACTERS };
}

/** Bound the complete entry, not each block independently, to fit API responses. */
export function boundLogContent(content: readonly RunLogContent[]): RunLogContent[] {
  const safeBlocks = content.map((block) => {
    const safe = logContent(block.kind, block.text);
    return { ...safe, role: block.role, truncated: safe.truncated || block.truncated };
  });
  let remaining = MAX_LOG_CONTENT_CHARACTERS;
  // Allocate short blocks first, then divide the remainder among long blocks.
  // A long reasoning block must not crowd out the actual response.
  const allowances = new Map<number, number>();
  const sorted = safeBlocks.map((block, index) => ({ index, length: block.text.length })).sort((a, b) => a.length - b.length);
  sorted.forEach(({ index, length }, position) => {
    const allowance = Math.min(length, Math.floor(remaining / (sorted.length - position)));
    allowances.set(index, allowance);
    remaining -= allowance;
  });
  return safeBlocks.map((block, index) => {
    const text = block.text.slice(0, allowances.get(index));
    return { ...block, text, truncated: block.truncated || text.length < block.text.length };
  });
}

/** Read only exposed text/JSON content. Signatures and redacted reasoning bytes are never decoded. */
export function messageLogContent(value: unknown, kind: 'request' | 'response' | 'tool_result'): RunLogContent[] {
  const parsed = parseLogJson(value);
  if (typeof parsed === 'string') return parsed.trim() ? [logContent(kind, parsed)] : [];
  if (!parsed || typeof parsed !== 'object') return [];
  if (Array.isArray(parsed)) return boundLogContent(parsed.flatMap((part) => messageLogContent(part, kind)));
  const item = parsed as Record<string, unknown>;
  if (item['role'] === 'system') return [];
  if (item['role'] === 'user' || item['role'] === 'assistant' || item['role'] === 'tool') {
    const role = item['role'];
    return messageLogContent(item['content'] ?? item['parts'], kind).map((block) => ({ ...block, role }));
  }
  const reasoning = item['reasoning'] ?? (item['type'] === 'reasoningBlock' ? item : undefined);
  if (reasoning && typeof reasoning === 'object') {
    const text = (reasoning as Record<string, unknown>)['text'];
    return kind === 'response' && typeof text === 'string' && text.trim() ? [logContent('reasoning', text)] : [];
  }
  if (item['type'] === 'reasoning' || item['type'] === 'reasoning_summary') {
    const text = item['text'] ?? item['content'];
    return kind === 'response' && typeof text === 'string' ? [logContent('reasoning', text)] : [];
  }
  if (typeof item['text'] === 'string') return [logContent(kind, item['text'])];
  if (item['type'] === 'text' && typeof item['content'] === 'string') return [logContent(kind, item['content'])];
  if ('json' in item) return [logContent(kind, item['json'])];
  if (item['toolUse'] || item['type'] === 'toolUseBlock' || item['type'] === 'tool_call') {
    const tool = (item['toolUse'] ?? item) as Record<string, unknown>;
    return [logContent(kind, { tool: tool['name'], arguments: tool['input'] ?? tool['arguments'] })];
  }
  if (item['toolResult']) return messageLogContent(item['toolResult'], kind);
  if (item['type'] === 'tool_call_response') return messageLogContent(item['response'], kind);
  if ('content' in item) return messageLogContent(item['content'], kind);
  if ('parts' in item) return messageLogContent(item['parts'], kind);
  // Text parts can themselves contain a JSON response rather than a message
  // envelope. Preserve that structured response instead of silently dropping it.
  return typeof value === 'string' ? [logContent(kind, parsed)] : [];
}
