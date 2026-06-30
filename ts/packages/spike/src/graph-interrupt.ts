/**
 * WS-0 Spike 1 — Graph interrupt → resume (the HITL mechanism).
 *
 * ThreatForest's interviewer / threat_review / scanner_review nodes pause the
 * Strands Graph for human input via `event.interrupt()` and resume with the
 * user's answer. This spike proves the TS SDK reproduces that exact contract:
 *
 *   1. A 2-node Graph (producer → reviewer).
 *   2. A `BeforeNodeCallEvent` hook on `reviewer` calls `event.interrupt()`.
 *   3. First run halts with status INTERRUPTED and a pending interrupt whose
 *      `reason` carries the question payload (what the UI would render).
 *   4. Resume by invoking the SAME graph instance with
 *      `[new InterruptResponseContent({ interruptId, response })]`.
 *   5. On resume the hook's `interrupt()` returns the response; the run COMPLETES.
 *
 * No Bedrock / network: both nodes are deterministic custom Nodes, so this
 * isolates the interrupt machinery from any model dependency.
 */
import {
  Graph,
  InterruptResponseContent,
  TextBlock,
  type Interrupt,
} from '@strands-agents/sdk';
import {
  Node,
  BeforeNodeCallEvent,
  Status,
  type MultiAgentInput,
  type MultiAgentState,
  type NodeInputOptions,
  type NodeResultUpdate,
  type MultiAgentStreamEvent,
} from '@strands-agents/sdk/multiagent';

/** Minimal deterministic node: records a line into shared app-state and emits text. */
class EchoNode extends Node {
  override readonly type = 'echoNode';
  constructor(
    id: string,
    private readonly produce: (state: MultiAgentState) => string,
  ) {
    super(id, {});
  }
  // eslint-disable-next-line require-yield
  override async *handle(
    _input: MultiAgentInput,
    state: MultiAgentState,
    _options?: NodeInputOptions,
  ): AsyncGenerator<MultiAgentStreamEvent, NodeResultUpdate, undefined> {
    const text = this.produce(state);
    state.app.set(`${this.id}.output`, text);
    return { content: [new TextBlock(text)] };
  }
}

async function main(): Promise<void> {
  const producer = new EchoNode('producer', () => 'producer: drafted 3 threats');
  const reviewer = new EchoNode('reviewer', (state) => {
    const decision = state.app.get('reviewer.decision') ?? '(none)';
    return `reviewer: finalized with human decision = ${JSON.stringify(decision)}`;
  });

  const graph = new Graph({
    id: 'spike-interrupt',
    nodes: [producer, reviewer],
    edges: [['producer', 'reviewer']],
  });

  // HITL hook: before `reviewer` runs, pause for human input. On first pass this
  // throws InterruptError (run -> INTERRUPTED); on resume it returns the response.
  graph.addHook(BeforeNodeCallEvent, (event) => {
    if (event.nodeId !== 'reviewer') return;
    const decision = event.interrupt<string>({
      name: 'threat_review',
      reason: {
        phase: 'threat_review',
        questions: ['Keep all 3 threats?', 'Re-prioritize any?'],
      },
    });
    // Reached only on resume — stash the human answer for the node to read.
    event.state.app.set('reviewer.decision', decision);
  });

  // ---- Run 1: expect INTERRUPTED with a pending interrupt --------------------
  const first = await graph.invoke('Analyze repo X');
  console.log('[run1] status =', first.status);
  const pending: Interrupt[] = first.interrupts ?? [];
  console.log('[run1] pending interrupts =', pending.length);
  if (first.status !== Status.INTERRUPTED || pending.length !== 1) {
    throw new Error(
      `SPIKE FAIL: expected INTERRUPTED with 1 interrupt, got ${first.status} / ${pending.length}`,
    );
  }
  const itr = pending[0]!;
  console.log('[run1] interrupt.name =', itr.name);
  console.log('[run1] interrupt.reason =', JSON.stringify(itr.reason));
  console.log('[run1] interrupt.source =', itr.source); // expect 'multiagent-hook'

  // ---- Run 2: resume same instance with the human response -------------------
  const resumed = await graph.invoke([
    new InterruptResponseContent({
      interruptId: itr.id,
      response: 'approved: drop threat #2',
    }),
  ]);
  console.log('[run2] status =', resumed.status);
  const finalText = resumed.results
    .flatMap((r) => r.content)
    .map((b) => ('text' in b ? (b as TextBlock).text : ''))
    .join(' | ');
  console.log('[run2] terminus content =', finalText);

  if (resumed.status !== Status.COMPLETED) {
    throw new Error(`SPIKE FAIL: expected COMPLETED on resume, got ${resumed.status}`);
  }
  if (!finalText.includes('approved: drop threat #2')) {
    throw new Error('SPIKE FAIL: human decision did not flow into the reviewer node');
  }

  console.log('\n✅ SPIKE 1 PASS — Graph interrupt → resume works (HITL contract holds).');
}

main().catch((err) => {
  console.error('\n❌ SPIKE 1 FAIL:', err);
  process.exit(1);
});
