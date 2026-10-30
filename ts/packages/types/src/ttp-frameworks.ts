import { z } from 'zod';

/** Mapper framework IDs accepted by the ThreatForest ML service. */
export const TTP_FRAMEWORK_IDS = ['attack', 'atlas', 'wiz'] as const;

export const TtpFrameworkIdSchema = z.enum(TTP_FRAMEWORK_IDS);
export type TtpFrameworkId = z.infer<typeof TtpFrameworkIdSchema>;

export interface TtpFrameworkDefinition {
  name: string;
  description: string;
}

/** User-facing metadata for every mapper framework, keyed by its wire ID. */
export const TTP_FRAMEWORK_CATALOG = {
  attack: {
    name: 'MITRE ATT&CK Enterprise',
    description: 'Cloud, network, and endpoint attack techniques.',
  },
  atlas: {
    name: 'MITRE ATLAS',
    description: 'Adversarial threats to AI and machine learning systems.',
  },
  wiz: {
    name: 'Wiz Cloud Threat Landscape',
    description: 'Cloud-native attack techniques.',
  },
} as const satisfies Record<TtpFrameworkId, TtpFrameworkDefinition>;

/** Hosted runs map against all supported knowledge bases by default. */
export const DEFAULT_TTP_FRAMEWORK_IDS: readonly TtpFrameworkId[] =
  TTP_FRAMEWORK_IDS;
