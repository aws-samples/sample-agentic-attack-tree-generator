import { z } from 'zod';

export const ScanInputSchema = z.object({
  project_path: z.string().describe('Absolute path to the project directory to threat-model.'),
  frameworks: z
    .array(z.string())
    .nullable()
    .default(null)
    .describe('MITRE frameworks to map against: "attack", "atlas", "wiz". Null = all.'),
});
export type ScanInput = z.infer<typeof ScanInputSchema>;

export const GetRunInputSchema = z.object({
  run_id: z.string().describe('The run_id returned by threatforest_scan.'),
});
export type GetRunInput = z.infer<typeof GetRunInputSchema>;

export const GetFindingsInputSchema = z.object({
  run_id: z.string().describe('The run_id of a completed scan.'),
});
export type GetFindingsInput = z.infer<typeof GetFindingsInputSchema>;
