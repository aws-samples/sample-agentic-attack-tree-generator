/**
 * `temperature` compatibility for Bedrock models.
 *
 * WHY THIS EXISTS
 * ---------------
 * Newer Anthropic models reject any request carrying `temperature`
 * ("`temperature` is deprecated for this model"), and Bedrock surfaces that as a
 * validation error on the FIRST call — which kills the scanner agent and fails a
 * whole run in under a second.
 *
 * This guard has now been patched three times, each encoding the model naming of
 * its moment:
 *   1. `modelId.includes('claude-opus-4-7')`            — literal
 *   2. `/claude-opus-4-(\d{1,2})(?!\d)/` with minor >= 7 — generalised over 4.x minors
 *   3. …and then Claude 5 shipped. `claude-opus-5` has no `-4-` segment, so the
 *      regex did not match, temperature was sent, and scans died instantly again.
 *      (Verified against live Bedrock: claude-opus-5, claude-sonnet-5 and
 *      claude-fable-5 all reject it; sonnet-4-6, opus-4-6, opus-4-5 and
 *      haiku-4-5 all accept it.)
 *
 * A fourth hardcoded pattern would break on Claude 6. So the policy here is
 * two-layer:
 *
 *   FAST PATH   `modelDeprecatesTemperature()` — a best-effort predicate that
 *               recognises the families we already know about, so the common
 *               case costs no wasted API call.
 *   SAFETY NET  `TemperatureFallbackBedrockModel` — if a model we did NOT
 *               predict rejects temperature, catch that one error, drop the
 *               parameter, and transparently retry. Self-correcting for any
 *               future model, with no code change.
 *
 * The negative result is remembered per model id, so only the first call of a
 * process pays the retry; the other agents in the pipeline skip temperature
 * outright.
 */
import { BedrockModel } from '@strands-agents/sdk';
import type { ModelStreamEvent, StreamOptions } from '@strands-agents/sdk';
import type { Message } from '@strands-agents/sdk';

/**
 * Model ids observed to reject `temperature` at runtime.
 *
 * Process-lifetime only, and deliberately not persisted: it is a cache of an
 * observation, not configuration. Populated by the fallback below so that after
 * one agent discovers the incompatibility, the remaining agents in the run omit
 * temperature from their first call.
 */
const observedDeprecations = new Set<string>();

/** Test seam. */
export function resetObservedTemperatureDeprecations(): void {
  observedDeprecations.clear();
}

/** Whether a runtime observation has already ruled temperature out for this id. */
export function hasObservedTemperatureDeprecation(modelId: string): boolean {
  return observedDeprecations.has(modelId);
}

/**
 * Best-effort predicate for model families known to reject `temperature`.
 *
 * Intentionally a FAST PATH, not the source of truth — the runtime fallback is
 * what makes an unrecognised model work. Two rules:
 *
 *   - `claude-opus-4-<minor>` with minor >= 7 (4.7, 4.8, … 4.10).
 *     The `(?!\d)` stops a date-suffixed id (…opus-4-20250514…, i.e. Opus 4.0)
 *     from parsing the date as the minor.
 *   - `claude-<family>-<major>` with major >= 5, for any family
 *     (opus/sonnet/haiku/fable/…). Claude 5 dropped temperature across the
 *     board, and the `(?![\d-])` keeps `claude-opus-4-5…` — a 4.x minor, which
 *     DOES accept temperature — from matching as "major 4".
 */
export function modelDeprecatesTemperature(modelId: string): boolean {
  const opus4Minor = /claude-opus-4-(\d{1,2})(?!\d)/.exec(modelId);
  if (opus4Minor && Number(opus4Minor[1]) >= 7) return true;

  // `claude-opus-5`, `claude-sonnet-5`, `claude-fable-5`, `claude-opus-6`, …
  // The negative lookahead excludes `claude-opus-4-5` (major 4, minor 5) and
  // `claude-sonnet-4-…`, which are handled by the rule above.
  const major = /claude-[a-z]+-(\d{1,2})(?![\d-])/.exec(modelId);
  if (major && Number(major[1]) >= 5) return true;

  return false;
}

/** Does this error mean the model refused the `temperature` parameter? */
export function isTemperatureRejection(error: unknown): boolean {
  // Walk the cause chain: the SDK re-wraps provider errors into ModelError, so
  // the original text may be one or more levels down.
  let current: unknown = error;
  for (let depth = 0; current instanceof Error && depth < 5; depth++) {
    // Match on the parameter plus a rejection verb rather than the exact
    // sentence, so a reworded AWS message still lands. Bedrock's current text is
    // "The model returned the following errors: `temperature` is deprecated for
    // this model."
    if (
      /temperature/i.test(current.message) &&
      /(deprecat|not supported|unsupported|unexpected|invalid|cannot be)/i.test(current.message)
    ) {
      return true;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return false;
}

/**
 * A `BedrockModel` that drops `temperature` and retries once if the model
 * rejects it.
 *
 * SAFETY OF THE RETRY: `temperature` is rejected as a request-validation error,
 * so it fails before any content is produced. The retry is therefore only taken
 * when ZERO events have been yielded — never mid-stream, where re-running would
 * duplicate content the agent loop has already consumed.
 */
export class TemperatureFallbackBedrockModel extends BedrockModel {
  override async *stream(
    messages: Message[],
    options?: StreamOptions,
  ): AsyncGenerator<ModelStreamEvent> {
    let yieldedAny = false;
    try {
      for await (const event of super.stream(messages, options)) {
        yieldedAny = true;
        yield event;
      }
      return;
    } catch (error) {
      const temperatureSet = this.getConfig().temperature !== undefined;
      // Only retry a clean, pre-content failure that we can actually fix.
      if (yieldedAny || !temperatureSet || !isTemperatureRejection(error)) throw error;

      const modelId = this.getConfig().modelId ?? '<unknown>';
      observedDeprecations.add(modelId);
      this.updateConfig({ temperature: undefined });
      // eslint-disable-next-line no-console
      console.warn(
        `[providers] ${modelId} rejected the \`temperature\` parameter; retrying without it ` +
          '(and omitting it for the rest of this process). Add it to ' +
          'modelDeprecatesTemperature() in temperature.ts to skip this probe.',
      );
    }

    // Outside the catch so a failure here propagates as itself rather than as a
    // confusing "error while handling error".
    for await (const event of super.stream(messages, options)) {
      yield event;
    }
  }
}
