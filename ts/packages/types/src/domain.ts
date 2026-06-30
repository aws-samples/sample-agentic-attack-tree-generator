/**
 * Core domain schemas — mirror the Python dataclasses in
 * `src/threatforest/types/{threat,attack_tree,ttp,mitigation,project,state}.py`.
 *
 * These are the structured outputs the agent pipeline produces and the UI
 * renders. Defaults match the Python dataclass field defaults so the on-disk
 * state JSON (`scanner_context.json`, `threats.json`, `attack_trees.json`,
 * `ttp_candidates.json`, `mitigations.json`) round-trips unchanged.
 */
import { z } from 'zod';

// --- project.py : ProjectContext (scanner output) --------------------------
export const ProjectContextSchema = z.object({
  tech_stack: z.string().default(''),
  cloud_provider: z.string().default(''), // "aws" | "gcp" | "azure" | "hybrid" | "none"
  services: z.array(z.string()).default([]),
  auth_mechanisms: z.array(z.string()).default([]),
  security_controls: z.record(z.string(), z.string()).default({}),
  data_flows: z.array(z.string()).default([]),
  files_analyzed: z.array(z.string()).default([]),
  files_skipped_reason: z.array(z.string()).default([]),
  repo_size_category: z.string().default(''), // "small" | "large"
});
export type ProjectContext = z.infer<typeof ProjectContextSchema>;

// --- threat.py : Threat ----------------------------------------------------
export const ThreatSchema = z.object({
  id: z.string().default(''),
  title: z.string().default(''),
  description: z.string().default(''),
  threat_source: z.string().default(''), // "generated" | "user_provided"
  affected_components: z.array(z.string()).default([]),
});
export type Threat = z.infer<typeof ThreatSchema>;

// --- attack_tree.py : AttackStep / AttackTree ------------------------------
export const AttackStepSchema = z.object({
  id: z.string().default(''),
  description: z.string().default(''),
  parent_id: z.string().default(''),
  is_leaf: z.boolean().default(false),
  feasibility_note: z.string().default(''),
  // Attacker factors (empty on fact nodes).
  skill_required: z.string().default(''), // low|med|high
  access_required: z.string().default(''), // none|authenticated|privileged
  detectability: z.string().default(''), // low|med|high
  exploit_maturity: z.string().default(''), // theoretical|poc|weaponised
  // Computed by the probability stage.
  probability: z.number().default(0),
  probability_rationale: z.string().default(''),
  reach_probability: z.number().default(0),
});
export type AttackStep = z.infer<typeof AttackStepSchema>;

export const AttackTreeSchema = z.object({
  id: z.string().default(''),
  threat_id: z.string().default(''),
  root_goal: z.string().default(''),
  steps: z.array(AttackStepSchema).default([]),
});
export type AttackTree = z.infer<typeof AttackTreeSchema>;

// --- ttp.py : TTPCandidate / TTPMapping ------------------------------------
export const TTPCandidateSchema = z.object({
  technique_id: z.string().default(''),
  technique_name: z.string().default(''),
  similarity_score: z.number().default(0),
  rank: z.number().int().default(0),
});
export type TTPCandidate = z.infer<typeof TTPCandidateSchema>;

export const TTPMappingSchema = z.object({
  attack_step_id: z.string().default(''),
  technique_id: z.string().default(''),
  technique_name: z.string().default(''),
  similarity_score: z.number().default(0),
  top_k_candidates: z.array(TTPCandidateSchema).default([]),
  reviewer_overrode_top1: z.boolean().default(false),
  reviewer_reasoning: z.string().default(''),
});
export type TTPMapping = z.infer<typeof TTPMappingSchema>;

// --- mitigation.py : Evidence / ControlCandidate / Mitigation --------------
export const EvidenceSchema = z.object({
  source_type: z.string().default(''), // "control_catalog" | "attack_technique" | "project_file"
  source_ref: z.string().default(''),
  excerpt: z.string().default(''),
  relevance: z.string().default(''),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export const ControlCandidateSchema = z.object({
  control_id: z.string().default(''),
  control_name: z.string().default(''),
  control_description: z.string().default(''),
  similarity_score: z.number().default(0),
  rank: z.number().int().default(0),
});
export type ControlCandidate = z.infer<typeof ControlCandidateSchema>;

export const RemediationType = z.enum([
  'quick_win',
  'short_term',
  'medium_term',
  'long_term',
  'monitoring',
]);
export type RemediationTypeT = z.infer<typeof RemediationType>;

export const MitigationSchema = z.object({
  attack_step_id: z.string().default(''),
  technique_id: z.string().default(''),
  mitigation_text: z.string().default(''),
  implementation_guidance: z.string().default(''),
  control_candidates: z.array(ControlCandidateSchema).default([]),
  selected_control_id: z.string().default(''),
  priority: z.number().int().default(0),
  evidence: z.array(EvidenceSchema).default([]),
});
export type Mitigation = z.infer<typeof MitigationSchema>;

// --- state.py : NodeResult (graph node state pointer) ----------------------
export const GraphNodeRoute = z.enum(['pass', 'reject', 'feedback']);
export const NodeResultSchema = z.object({
  state_file: z.string(),
  summary: z.string(),
  route: GraphNodeRoute,
  feedback: z.string().nullable().default(null),
  retry_count: z.number().int().default(0),
  max_retries: z.number().int().default(2),
});
export type NodeResult = z.infer<typeof NodeResultSchema>;
