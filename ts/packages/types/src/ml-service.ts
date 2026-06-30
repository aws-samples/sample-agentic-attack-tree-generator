/**
 * ML-service contract — mirrors `src/ml_service/app.py` (WS-1).
 *
 * The TS TTP stage (WS-3) is a client of this Python service; these schemas are
 * the wire contract for `/embed` and `/match_steps`. Field names and shapes are
 * byte-identical to the Pydantic models so the cross-process call is 1:1 with the
 * legacy in-process `TTCMatcher.match_steps` output.
 */
import { z } from 'zod';

export const EmbedRequestSchema = z.object({
  texts: z.array(z.string()).default([]),
});
export type EmbedRequest = z.infer<typeof EmbedRequestSchema>;

export const EmbedResponseSchema = z.object({
  vectors: z.array(z.array(z.number())),
});
export type EmbedResponse = z.infer<typeof EmbedResponseSchema>;

export const MatchStepsRequestSchema = z.object({
  steps: z.array(z.string()).default([]),
  top_k: z.number().int().default(3),
  min_similarity: z.number().nullable().default(null),
  frameworks: z.array(z.string()).nullable().default(null),
});
export type MatchStepsRequest = z.infer<typeof MatchStepsRequestSchema>;

/** One technique candidate — matches TTCMatcher's per-match dict exactly. */
export const TechniqueMatchSchema = z.object({
  technique_id: z.string(),
  name: z.string(),
  description: z.string(),
  kill_chain_phases: z.array(z.string()),
  similarity: z.number(),
  confidence: z.enum(['high', 'medium', 'low']),
  framework: z.string(),
});
export type TechniqueMatch = z.infer<typeof TechniqueMatchSchema>;

export const StepMatchSchema = z.object({
  attack_step: z.string(),
  matches: z.array(TechniqueMatchSchema),
});
export type StepMatch = z.infer<typeof StepMatchSchema>;

export const MatchStepsResponseSchema = z.object({
  results: z.array(StepMatchSchema),
});
export type MatchStepsResponse = z.infer<typeof MatchStepsResponseSchema>;
