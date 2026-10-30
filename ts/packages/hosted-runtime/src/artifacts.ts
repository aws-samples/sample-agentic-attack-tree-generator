import {
  ArtifactIdSchema,
  ArtifactRefSchema,
  type ArtifactRef,
} from '@threatforest/types';
import type { ArtifactStore, Clock, TranscriptWriteInput } from './contracts.js';
import { systemClock } from './contracts.js';
import { canonicalJson, sha256 } from './util.js';

export class InMemoryArtifactStore implements ArtifactStore {
  readonly #artifacts = new Map<string, { ref: ArtifactRef; content: string }>();
  readonly #clock: Clock;

  constructor(clock: Clock = systemClock) {
    this.#clock = clock;
  }

  async putTranscript(input: TranscriptWriteInput): Promise<ArtifactRef> {
    const content = canonicalJson(input.transcript);
    const digest = sha256(content);
    const artifactId = ArtifactIdSchema.parse(
      `transcript_${sha256(`${input.idempotency_key}\0${digest}`).slice(0, 48)}`,
    );
    const current = this.#artifacts.get(artifactId);
    if (current !== undefined) {
      if (current.content !== content) {
        throw new Error(`artifact ${artifactId} already contains different content`);
      }
      return structuredClone(current.ref);
    }
    const ref = ArtifactRefSchema.parse({
      artifact_id: artifactId,
      kind: 'transcript',
      version: input.revision,
      content_type: 'application/json',
      size_bytes: Buffer.byteLength(content),
      sha256: digest,
      created_at: this.#clock.now().toISOString(),
    });
    this.#artifacts.set(artifactId, { ref, content });
    return structuredClone(ref);
  }

  has(artifactId: string): boolean {
    return this.#artifacts.has(artifactId);
  }

  read(artifactId: string): string | null {
    return this.#artifacts.get(artifactId)?.content ?? null;
  }
}
