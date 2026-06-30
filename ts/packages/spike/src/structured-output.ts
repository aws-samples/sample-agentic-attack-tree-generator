/**
 * WS-0 Spike 2 — Agent + tool() (Zod) + structuredOutputSchema on Bedrock.
 *
 * ThreatForest's mitigation/threat agents rely on Pydantic-validated tool output
 * and structured results. This spike proves the TS SDK equivalent end-to-end:
 *
 *   1. A `tool()` with a Zod input schema the model can call.
 *   2. An `Agent` with `structuredOutputSchema` (Zod) that must emit a typed object.
 *   3. A real Bedrock round-trip; assert the parsed `structuredOutput` matches the schema.
 *
 * Requires AWS credentials + Bedrock access. Region/model come from env with
 * sensible defaults (override via BEDROCK_REGION / TF_SPIKE_MODEL_ID).
 */
import { Agent, BedrockModel, tool } from '@strands-agents/sdk';
import { z } from 'zod';

const REGION = process.env.BEDROCK_REGION ?? process.env.AWS_REGION ?? 'us-east-1';
const MODEL_ID = process.env.TF_SPIKE_MODEL_ID ?? 'global.anthropic.claude-sonnet-4-6';

// Zod schema mirroring the shape of a ThreatForest "threat" record.
const ThreatList = z.object({
  threats: z
    .array(
      z.object({
        id: z.string(),
        title: z.string(),
        severity: z.enum(['low', 'medium', 'high', 'critical']),
        affected_components: z.array(z.string()),
      }),
    )
    .min(1),
});

// A tool the model may call (proves tool() + Zod arg validation wiring).
const componentLookup = tool({
  name: 'list_components',
  description: 'List the known components of the system under analysis.',
  inputSchema: z.object({ area: z.string().describe('subsystem area to enumerate') }),
  callback: ({ area }) => ({
    area,
    components: ['api-gateway', 'auth-service', 's3-bucket', 'lambda-fn'],
  }),
});

async function main(): Promise<void> {
  console.log(`[spike2] region=${REGION} model=${MODEL_ID}`);
  const agent = new Agent({
    model: new BedrockModel({ modelId: MODEL_ID, region: REGION, maxTokens: 2048 }),
    systemPrompt:
      'You are a threat-modeling assistant. Use the list_components tool to ground your ' +
      'analysis, then produce a concise threat list as structured output.',
    tools: [componentLookup],
    structuredOutputSchema: ThreatList,
    printer: false,
  });

  const result = await agent.invoke(
    'Identify the top 2-3 security threats for a public-facing serverless API. ' +
      'Call list_components first, then return the structured threat list.',
  );

  const out = result.structuredOutput;
  console.log('[spike2] raw structuredOutput =', JSON.stringify(out, null, 2));

  // Re-validate defensively — the SDK should have validated, but assert the contract.
  const parsed = ThreatList.parse(out);
  console.log(`[spike2] parsed ${parsed.threats.length} threat(s):`);
  for (const t of parsed.threats) {
    console.log(`  - [${t.severity}] ${t.id}: ${t.title} (${t.affected_components.join(', ')})`);
  }

  console.log('\n✅ SPIKE 2 PASS — Agent + Zod tool + structuredOutputSchema on Bedrock works.');
}

main().catch((err) => {
  console.error('\n❌ SPIKE 2 FAIL:', err);
  process.exit(1);
});
