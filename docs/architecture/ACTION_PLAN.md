# Graph Architecture — Refactoring Action Plan

Reference: [graph-swarm-architecture.md](./graph-swarm-architecture.md)

## Current Structure → Target Structure

```
CURRENT                                         TARGET
src/threatforest/                               src/threatforest/
├── cli.py                                      ├── cli.py (update imports)
├── orchestrator.py          ← DELETE           ├── config.py
├── config.py                                   ├── graph.py              ← NEW: builds & runs the Strands Graph
├── modules/                                    │
│   ├── agents/                                 ├── agents/               ← NEW top-level
│   │   ├── repository_analysis_agent.py        │   ├── scanner/
│   │   ├── context_extractor_agent.py          │   │   ├── agent.py      (Scanner Agent)
│   │   ├── threat_generation_agent.py          │   │   ├── verifier.py   (Context Verifier)
│   │   ├── parser_agent.py                     │   │   └── prompt.md
│   │   └── tree_generator_agent.py             │   ├── threat/
│   ├── core/                                   │   │   ├── agent.py      (Threat Agent)
│   │   ├── base_agent.py                       │   │   ├── verifier.py   (Threat Verifier)
│   │   ├── providers/                          │   │   └── prompt.md
│   │   ├── state.py                            │   ├── tree/
│   │   ├── state_manager.py                    │   │   ├── agent.py      (Tree Generator)
│   │   ├── context.py                          │   │   ├── verifier.py   (Tree Verifier — structure + feasibility)
│   │   ├── file_discovery.py                   │   │   └── prompt.md
│   │   └── progress_emitter.py                 │   ├── ttp/
│   ├── graph/               ← Neptune stuff    │   │   ├── embedding.py  (TTP Embedding Model)
│   │   ├── embedding_service.py                │   │   ├── reviewer.py   (TTP Reviewer)
│   │   ├── graph_builder.py                    │   │   ├── coverage.py   (TTP Coverage Check — deterministic)
│   │   ├── graph_store.py                      │   │   └── prompt.md
│   │   ├── vector_search.py                    │   ├── mitigation/
│   │   └── types.py                            │   │   ├── embedding.py  (Control Embedding Model)
│   ├── types/                                 │   │   ├── agent.py      (Mitigation Agent)
│   │   ├── project_models.py                   │   │   ├── verifier.py   (Mitigation Verifier)
│   │   ├── threat_models.py                    │   │   └── prompt.md
│   │   └── attack_tree_models.py               │   └── report/
│   ├── tools/                                  │       ├── agent.py      (Report Generator)
│   │   └── read_only_editor.py                 │       ├── verifier.py   (Report Verifier)
│   ├── utils/                                  │       └── prompt.md
│   ├── visualization/                          │
│   ├── workflow/                               ├── tools/                ← NEW top-level
│   │   ├── context_analysis/                   │   ├── sandboxed_file.py (sandboxed file_read/file_write)
│   │   ├── information_extraction/             │   └── structural_analyzer.py (shared tool)
│   │   ├── attack_tree_generator/              │
│   │   ├── ttc_mappings/                       ├── types/               ← NEW top-level
│   │   └── summary_generator/                  │   ├── state.py          (file-based state models)
│   └── cli/                                    │   ├── project.py        (ProjectContext)
├── prompts/                                    │   ├── threat.py
├── tracing/                                    │   ├── attack_tree.py
└── data/                                       │   ├── ttp.py            (TTPMapping, TTPCandidate)
                                                │   ├── mitigation.py     (Mitigation, ControlCandidate, Evidence)
                                                │   └── quality.py        (QualityWarning)
                                                │
                                                ├── embedding/            ← NEW: shared embedding infra
                                                │   └── service.py        (reuse from modules/graph/embedding_service.py)
                                                │
                                                ├── modules/              ← KEEP (legacy, shrink over time)
                                                │   ├── core/providers/   (keep — model provider factory)
                                                │   ├── visualization/    (keep — HTML dashboard)
                                                │   ├── cli/              (keep — wizard, display)
                                                │   └── utils/            (keep — logger, config_manager)
                                                │
                                                ├── tracing/              (keep as-is)
                                                └── data/                 (keep as-is)
```

## Phases

### Phase 1: Scaffold & Models
Create the new directory structure and data models. No behavior changes, no broken imports.

- [ ] Create `agents/` directory with subfolders: `scanner/`, `threat/`, `tree/`, `ttp/`, `mitigation/`, `report/`
- [ ] Create `tools/` directory
- [ ] Create `types/` directory
- [ ] Create `embedding/` directory
- [ ] Write new data models in `types/`:
  - `state.py` — `NodeResult` (state_file, summary, route, feedback, retry_count)
  - `project.py` — `ProjectContext` (from architecture doc)
  - `threat.py` — `Threat`
  - `attack_tree.py` — `AttackTree`, `AttackStep`
  - `ttp.py` — `TTPMapping`, `TTPCandidate`
  - `mitigation.py` — `Mitigation`, `ControlCandidate`, `Evidence`
  - `quality.py` — `QualityWarning`
- [ ] Write `tools/sandboxed_file.py` — `make_sandboxed_file_read()`, `make_sandboxed_file_write()`
- [ ] Write `tools/structural_analyzer.py` — wraps `read_only_editor` + `file_read` with path sandboxing
- [ ] **Tests:**
  - `tests/types/` — serialization/deserialization for all data models, validation of required fields
  - `tests/tools/test_sandboxed_file.py` — path validation (allowed paths pass, disallowed paths raise `PermissionError`, `../` traversal blocked, symlink resolution)
  - `tests/tools/test_structural_analyzer.py` — read operations work within sandbox, write operations blocked

### Phase 2: Scanner Agent
First agent in the graph. Can be tested standalone.

- [ ] Write `agents/scanner/agent.py` — Scanner Agent (replaces `repository_analysis_agent.py` + `context_extractor_agent.py`)
- [ ] Write `agents/scanner/verifier.py` — Context Verifier
- [ ] Write `agents/scanner/prompt.md` — system prompt
- [ ] Migrate relevant logic from:
  - `modules/agents/repository_analysis_agent.py`
  - `modules/agents/context_extractor_agent.py`
  - `modules/workflow/context_analysis/`
  - `modules/core/file_discovery.py`
- [ ] Write state output to `.threatforest/state/scanner_context.json`
- [ ] **Tests:**
  - `tests/agents/test_scanner.py` — mock LLM, verify agent produces valid `ProjectContext`, verifier rejects incomplete context, adaptive depth logic (small vs large repo), file prioritization (skips UI/tests/generated code)

### Phase 3: Threat Agent
Depends on Scanner output.

- [ ] Write `agents/threat/agent.py` — Threat Agent (replaces `threat_generation_agent.py`)
- [ ] Write `agents/threat/verifier.py` — Threat Verifier
- [ ] Write `agents/threat/prompt.md`
- [ ] Migrate from:
  - `modules/agents/threat_generation_agent.py`
  - `modules/agents/parser_agent.py`
  - `modules/workflow/information_extraction/`
- [ ] Reads from `scanner_context.json`, writes to `threats.json`
- [ ] **Tests:**
  - `tests/agents/test_threat.py` — mock LLM, verify agent reads scanner state file and produces valid threats, verifier rejects low-quality threats, user-provided threats bypass agent but still go through verifier

### Phase 4: Tree Generator + Verifier
Verifier includes feasibility checking.

- [ ] Write `agents/tree/agent.py` — Tree Generator (replaces `tree_generator_agent.py`)
- [ ] Write `agents/tree/verifier.py` — Tree Verifier (structure + feasibility)
- [ ] Write `agents/tree/prompt.md`
- [ ] Migrate from:
  - `modules/agents/tree_generator_agent.py`
  - `modules/workflow/attack_tree_generator/`
- [ ] Reads from `threats.json` + `scanner_context.json`, writes to `attack_trees.json`
- [ ] **Tests:**
  - `tests/agents/test_tree.py` — mock LLM, verify agent produces valid attack trees, verifier rejects invalid structure, verifier rejects unfeasible steps (tech stack mismatch), retry loop respects max budget, over-budget annotates as low-confidence

### Phase 5: TTP Pipeline
Embedding model + LLM reviewer + deterministic coverage check.

- [ ] Move `modules/graph/embedding_service.py` → `embedding/service.py`
- [ ] Write `agents/ttp/embedding.py` — TTP Embedding Model (vector search against ATT&CK)
- [ ] Write `agents/ttp/reviewer.py` — TTP Reviewer (LLM picks from top-K)
- [ ] Write `agents/ttp/coverage.py` — TTP Coverage Check (deterministic)
- [ ] Write `agents/ttp/prompt.md`
- [ ] Migrate from:
  - `modules/workflow/ttc_mappings/` (matcher, enricher, mapping_processor)
  - `modules/graph/` (embedding_service, vector_search)
- [ ] Reads from `attack_trees.json`, writes `ttp_candidates.json` → `ttp_mappings.json`
- [ ] **Tests:**
  - `tests/agents/test_ttp.py` — embedding returns top-K candidates per step, reviewer overrides top-1 when incorrect (mock LLM), coverage check passes when all steps mapped, coverage check rejects and routes back when steps missing, end-to-end pipeline with mock embeddings

### Phase 6: Mitigation Pipeline
Conditional: AWS path uses Control Catalog embeddings, non-AWS skips to agent.

- [ ] Write `agents/mitigation/embedding.py` — Control Embedding Model
- [ ] Write `agents/mitigation/agent.py` — Mitigation Agent (with evidence)
- [ ] Write `agents/mitigation/verifier.py` — Mitigation Verifier
- [ ] Write `agents/mitigation/prompt.md`
- [ ] Migrate from:
  - `modules/workflow/ttc_mappings/mitigation_mapper.py`
  - `modules/workflow/ttc_mappings/mitigation_enricher.py`
- [ ] Reads from `ttp_mappings.json` + `scanner_context.json`, writes to `mitigations.json`
- [ ] **Tests:**
  - `tests/agents/test_mitigation.py` — AWS path: embedding returns top-5 controls, agent synthesizes mitigation with evidence; non-AWS path: embedding skipped, agent works from context only; verifier rejects generic boilerplate mitigations; evidence is present and references valid sources

### Phase 7: Report Generator

- [ ] Write `agents/report/agent.py` — Report Generator
- [ ] Write `agents/report/verifier.py` — Report Verifier
- [ ] Write `agents/report/prompt.md`
- [ ] Migrate from:
  - `modules/workflow/summary_generator/`
  - `modules/visualization/` (keep, but Report Agent calls it)
- [ ] **Tests:**
  - `tests/agents/test_report.py` — reads all state files, produces report, verifier rejects incomplete reports

### Phase 8: Graph Assembly
Wire everything together with Strands Graph.

- [ ] Write `graph.py`:
  - Build `GraphBuilder` with all nodes
  - Wire edges (data flow, retry, feedback)
  - Conditional edges (user threats? AWS project?)
  - Configure `max_node_executions`, `execution_timeout`
  - Configure `reset_on_revisit=True` for retry loops
- [ ] Update `cli.py` to call `graph.py` instead of `orchestrator.py`
- [ ] Delete `orchestrator.py`
- [ ] **Tests:**
  - `tests/test_graph.py` — full graph wiring: all nodes registered, edges correct, conditional edges route correctly (user threats, AWS check), retry edges respect budget, feedback loop from TTP to Tree Gen fires, graph completes end-to-end with mock agents
  - `tests/test_graph_state.py` — state files created in correct location, each agent only reads/writes its allowed paths, state survives graph interruption and resume

### Phase 9: Cleanup
Remove dead code from `modules/`.

- [ ] Delete `modules/agents/` (all migrated to `agents/`)
- [ ] Delete `modules/workflow/` (all migrated to `agents/` subfolders)
- [ ] Delete `modules/graph/` (migrated to `embedding/`)
- [ ] Delete `modules/core/state.py`, `state_manager.py`, `context.py` (replaced by `types/state.py`)
- [ ] Keep `modules/core/providers/`, `modules/utils/`, `modules/visualization/`, `modules/cli/`
- [ ] Update all imports across the codebase
- [ ] Run tests, fix breakages
- [ ] **Tests:**
  - Verify all existing tracing tests still pass (no import breakage)
  - Remove old tests that reference deleted modules: `test_attack_tree_models.py`, `test_attack_tree_models_simple.py`, `test_threat_models.py`, `test_threat_models_simple.py`, `test_project_models.py`, `test_project_models_simple.py`, `test_parser_formats.py`, `test_parser_formats_simple.py`, `test_agents_integration.py` (replaced by new tests)
  - Keep: `test_read_only_editor.py` (still relevant), `test_config.py`, `test_ui_display.py`, `test_threatcomposer_parsing.py`, all `test_*tracing*` / `test_*langfuse*` / `test_*score*` tests

## Key Principles

1. **Each phase is independently committable** — no big-bang refactor
2. **Old code stays working until Phase 8** — `orchestrator.py` still runs the v1 pipeline while we build v2 alongside it
3. **One agent subfolder = one graph node** — agent.py, verifier.py, prompt.md, nothing else
4. **Models are shared, tools are shared, agents are isolated** — agents only communicate through state files
5. **Prompts live next to their agent** — not in a global `prompts/` folder
