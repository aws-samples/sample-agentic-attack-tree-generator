/**
 * UI attack-tree graph schemas — mirror
 * `src/threatforest/modules/models/attack_tree_models.py`.
 *
 * This is the *render-facing* shape the dashboard consumes from
 * `threatforest_data.json` (distinct from the pipeline's `attack_tree.py`,
 * which is in domain.ts). It carries `mermaid_code`, enriched `ttc_mappings`,
 * and optional explicit node/edge lists the React Flow viewer + dagre layout use.
 *
 * Note the Pydantic field aliases: AttackEdge serializes as `{from, to}` (not
 * `from_node`/`to_node`). The schemas below use the wire names so the JSON the
 * UI reads validates directly.
 */
import { z } from 'zod';

export const NodeType = z.enum(['attack', 'goal', 'fact', 'technique', 'mitigation']);
export type NodeTypeT = z.infer<typeof NodeType>;

export const AttackNodeSchema = z.object({
  node_id: z.string(),
  label: z.string(),
  node_type: NodeType,
  full_label: z.string().nullable().default(null),
  color: z.string().nullable().default(null),
});
export type AttackNode = z.infer<typeof AttackNodeSchema>;

/** Serializes with `from`/`to` (Pydantic aliases on AttackEdge). */
export const AttackEdgeSchema = z.object({
  from: z.string(),
  to: z.string(),
});
export type AttackEdge = z.infer<typeof AttackEdgeSchema>;

/** Enriched, UI-facing TTP mapping (confidence allows the AWS boost up to 1.5). */
export const UiTTPMappingSchema = z.object({
  attack_step: z.string(),
  technique_id: z.string(),
  technique_name: z.string(),
  confidence: z.number().min(0).max(1.5),
  tactics: z.array(z.string()).default([]),
  technique_url: z.string().nullable().default(null),
  mitigations: z.array(z.record(z.string(), z.unknown())).nullable().default(null),
});
export type UiTTPMapping = z.infer<typeof UiTTPMappingSchema>;

export const UiAttackTreeSchema = z.object({
  threat_id: z.string(),
  threat_statement: z.string(),
  threat_category: z.string(),
  mermaid_code: z.string(),
  nodes: z.array(AttackNodeSchema).nullable().default(null),
  edges: z.array(AttackEdgeSchema).nullable().default(null),
  ttc_mappings: z.array(UiTTPMappingSchema).default([]),
  mapping_count: z.number().int().nullable().default(null),
});
export type UiAttackTree = z.infer<typeof UiAttackTreeSchema>;

/**
 * The `threatforest_data.json` bundle the report stage writes and the UI loads
 * via `/api/applications/{appId}/versions/{versionId}/data`. Kept permissive
 * (passthrough) on the envelope since the report bundle accretes summary fields;
 * the `attack_trees` array is the contract the graph viewer depends on.
 */
export const ThreatForestDataSchema = z
  .object({
    attack_trees: z.array(UiAttackTreeSchema).default([]),
  })
  .passthrough();
export type ThreatForestData = z.infer<typeof ThreatForestDataSchema>;
