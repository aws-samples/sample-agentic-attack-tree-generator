import { parseDocument } from 'yaml';
import type {
  FileDetection,
  SourceDocument,
  ThreatInputClassification,
} from './types.js';
import { decodeText } from './detection.js';

const THREAT_FILENAME =
  /(?:^|[._ -])(threats?|threat[ _-]?statements?|threat[ _-]?model)(?:[._ -]|$)/i;

export function classifyThreatInput(
  source: SourceDocument,
  detection: FileDetection,
): ThreatInputClassification {
  if (source.explicitRole === 'threat-input') {
    return {
      authoritative: true,
      confidence: 1,
      reasons: ['Caller explicitly supplied this object as a threat input'],
    };
  }

  const text = decodeText(source.bytes);
  if (text === null) {
    return {
      authoritative: false,
      confidence: 0.95,
      reasons: ['Binary input has no explicit threat-input role'],
    };
  }

  if (detection.kind === 'json') {
    const structured = classifyStructuredJson(text);
    if (structured !== null) {
      return structured;
    }
  }
  if (detection.kind === 'yaml') {
    const structured = classifyStructuredYaml(text);
    if (structured !== null) {
      return structured;
    }
  }

  const filenameMatch = THREAT_FILENAME.test(source.filename);
  const headingMatches = countMatches(text, /^#{1,6}\s+.*\bthreat(?:s| statements?)?\b/gim);
  const statementMatches = countMatches(text, /\*\*Threat Statement\*\*\s*:/gi);
  const numberedThreats = countMatches(text, /^#{1,6}\s+(?:T\d+\s*[-:]|Threat\s+\d+\b)/gim);
  const evidenceCount = headingMatches + statementMatches + numberedThreats;
  if (
    (filenameMatch && evidenceCount >= 2) ||
    statementMatches >= 2 ||
    numberedThreats >= 3
  ) {
    return {
      authoritative: true,
      confidence: filenameMatch ? 0.96 : 0.9,
      reasons: [
        ...(filenameMatch ? ['Filename identifies a supplied threat document'] : []),
        `Document contains ${evidenceCount} threat-structure indicators`,
      ],
    };
  }
  return {
    authoritative: false,
    confidence: evidenceCount === 0 ? 0.9 : 0.65,
    reasons: [
      filenameMatch
        ? 'Filename mentions threats, but document structure is insufficient to treat it as authoritative'
        : 'No authoritative threat-file structure was detected',
    ],
  };
}

function classifyStructuredJson(text: string): ThreatInputClassification | null {
  try {
    return classifyStructuredValue(JSON.parse(text) as unknown, 'JSON');
  } catch {
    return null;
  }
}

function classifyStructuredYaml(text: string): ThreatInputClassification | null {
  const document = parseDocument(text, { strict: true, uniqueKeys: true });
  if (document.errors.length > 0) {
    return null;
  }
  try {
    return classifyStructuredValue(document.toJS({ maxAliasCount: 100 }), 'YAML');
  } catch {
    return null;
  }
}

function classifyStructuredValue(
  value: unknown,
  format: 'JSON' | 'YAML',
): ThreatInputClassification | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const threatCollections = [
    record['threats'],
    record['threatStatements'],
    record['threat_statements'],
  ];
  const collection = threatCollections.find(
    (candidate) => Array.isArray(candidate) && candidate.length > 0,
  );
  if (!Array.isArray(collection)) {
    return null;
  }
  const structuredItems = collection.filter(isThreatLike);
  if (structuredItems.length === 0) {
    return null;
  }
  const threatComposer =
    record['schema'] !== undefined &&
    record['applicationInfo'] !== null &&
    typeof record['applicationInfo'] === 'object';
  return {
    authoritative: true,
    confidence: threatComposer ? 1 : 0.98,
    reasons: [
      threatComposer
        ? 'Threat Composer workspace contains a structured threats collection'
        : `${format} contains a structured threats collection`,
      `${structuredItems.length} threat-like entries were found`,
    ],
  };
}

function isThreatLike(value: unknown): boolean {
  if (typeof value === 'string') {
    return value.trim().length >= 20;
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const keys = new Set(Object.keys(value as Record<string, unknown>).map((key) => key.toLowerCase()));
  return (
    keys.has('content') ||
    keys.has('description') ||
    keys.has('statement') ||
    keys.has('threat_statement') ||
    keys.has('threatstatement') ||
    keys.has('title')
  );
}

function countMatches(value: string, expression: RegExp): number {
  return [...value.matchAll(expression)].length;
}
