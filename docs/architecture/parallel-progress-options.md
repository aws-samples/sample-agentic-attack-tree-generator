# Parallel Pipeline Progress Display — Design Options

## Problem Statement

After "Threat Generation" completes, the `parallel_pipeline` graph node fans out **per-threat** sub-pipelines that each run: **Tree Generation → TTP Enrichment → Mitigation Mapping** sequentially, but all threats execute **concurrently**. This means at any given moment, Threat 1 might be in Mitigation Mapping while Threat 5 is still generating its Attack Tree.

The current UI displays these as 3 **sequential** stages (indices 2→3→4), but the backend's `_poll_parallel_progress()` poller uses a "dominant stage" heuristic — it transitions the UI to whichever sub-stage the **furthest-along** threat has reached. This creates a confusing UX where:

- "Attack Tree Generation" quickly flips to "TTP Enrichment" as soon as the first threat finishes trees, even though most threats are still generating trees
- The worker grid (already implemented in `StageCard`) shows a mix of sub-stages that contradict the current stage label
- Overall progress percentages feel jumpy and non-monotonic

### Current Architecture

```
Graph Nodes:  scanner → threat → parallel_pipeline → report
                                      │
                                      ├── Threat 0: tree → ttp_embed → ttp_review → mitigation
                                      ├── Threat 1: tree → ttp_embed → ttp_review → mitigation
                                      ├── Threat 2: tree → ttp_embed → ttp_review → mitigation
                                      └── ...all concurrent via asyncio.gather()
```

```
UI Stages:  [Repo Analysis] → [Threat Gen] → [Attack Trees] → [TTP Enrichment] → [Mitigation] → [Dashboard]
                                                 ↑                    ↑                 ↑
                                              These 3 are actually happening IN PARALLEL, not sequentially
```

### Key Files

| File | Role |
|------|------|
| `src/server/executor.py` | `_poll_parallel_progress()` — polls `get_parallel_progress()` every 1s, emits stage transitions based on "dominant sub-stage" |
| `src/threatforest/agents/parallel.py` | Per-threat pipeline, shared `_progress` dict with `get_parallel_progress()` |
| `console-ui/src/pages/RunProgressPage.jsx` | WebSocket consumer, maintains `stages[]` state array |
| `console-ui/src/components/StageCard.jsx` | Renders each stage with progress bar, status text, worker grid |
| `src/server/run_manager.py` | `ProgressEvent` model, background thread execution |

---

## Option A: Single "Parallel Analysis" Stage with Per-Threat Grid

### Concept

Replace the 3 separate stages with **one combined "Parallel Analysis" stage** that shows all per-threat progress in an expanded worker grid. Each threat tile shows its current sub-stage with a mini status indicator. The overall progress reflects `completed_threats / total_threats`.

### UI Mockup

```
┌─────────────────────────────────────────────────────────┐
│  ✓ Repository Analysis                            42s   │
│  ✓ Threat Generation                              38s   │
│  ⟳ Parallel Analysis (5/12 threats complete)     1m 23s │
│    ┌──────────────────────────────────────────────────┐  │
│    │ ████████████████░░░░░░░░░░░  41%                │  │
│    ├──────────────────────────────────────────────────┤  │
│    │ ✅ T1: Done   │ ⚡ T5: 🤖 TTP  │ ⏳ T9: Queued │  │
│    │ ✅ T2: Done   │ ⚡ T6: 🌳 Tree │ ⏳ T10: Queued│  │
│    │ ✅ T3: Done   │ ⚡ T7: 🌳 Tree │ ⏳ T11: Queued│  │
│    │ ✅ T4: Done   │ ⚡ T8: 🛡️ Mit  │ ⏳ T12: Queued│  │
│    │ ✅ T5: Done   │                │               │  │
│    └──────────────────────────────────────────────────┘  │
│    🛡️ Mitigations for threat 8 generated                │
│  ○ Dashboard Generation                                 │
└─────────────────────────────────────────────────────────┘
```

### Backend Changes

**`executor.py`** — Simplify the poller to emit progress on a **single stage** called `"Parallel Analysis"`:

```python
# Replace STAGES concept — collapse 3 parallel stages into 1
NODE_LABELS = {
    "scanner": "Repository Analysis",
    "threat": "Threat Generation",
    "parallel_pipeline": "Parallel Analysis",   # ← single stage
    "report": "Dashboard Generation",
}
```

The `_poll_parallel_progress()` function simplifies dramatically — no more dominant-stage detection or stage transitions. Just emit `stage_progress` events with the worker grid:

```python
progress_callback(ProgressEvent(
    event_type="stage_progress",
    stage="Parallel Analysis",
    percentage=int(100 * done / total),
    message=f"{done}/{total} threats complete",
    details={"workers": workers, "total": total, "completed": done},
))
```

On `parallel_pipeline` completion, emit a single `stage_complete` with combined findings (trees + TTPs + mitigations).

**`RunProgressPage.jsx`** — Reduce STAGES to 4:

```javascript
const STAGES = [
  'Repository Analysis',
  'Threat Generation',
  'Parallel Analysis',
  'Dashboard Generation',
];
```

### Frontend Changes

- `StageCard.jsx` — The existing worker grid already handles this. Minor enhancement: add sub-stage icons and a "phase legend" row at the top of the grid.
- No new components needed.

### Pros
- **Honest** — accurately represents that these are parallel, not sequential
- **Simple** — removes the complex dominant-stage poller logic; ~50% less code in `_poll_parallel_progress()`
- **Per-threat visibility** — the worker grid already exists and shows real-time sub-stage per threat
- **Smooth progress** — percentage monotonically increases as threats complete
- **Minimal UI changes** — mostly backend simplification + stage list change

### Cons
- **Less granular stage visibility** — you can't see "TTP Enrichment is X% done" as a top-level stage
- **Fewer "completed" checkmarks** — pipeline goes from 6 completed stages to 4, which feels less satisfying
- **Loss of stage-level timing** — can't answer "how long did TTP Enrichment take?" from the UI (though sub-stage timing is still in the worker grid)

### Estimated Effort: **Small** (~2-3 hours)
- Backend: Simplify poller, update NODE_LABELS, remove stage transition logic
- Frontend: Update STAGES array, minor StageCard legend enhancement
- Tests: Update stage count expectations

---

## Option B: Concurrent Active Stages with Independent Progress

### Concept

When the parallel pipeline starts, **mark all 3 stages as "in-progress" simultaneously**. Each stage tracks its own progress independently based on how many threats have completed that particular sub-phase. Stages complete independently — "Attack Tree Generation" might finish at 80% overall while "Mitigation Mapping" is at 30%.

### UI Mockup

```
┌─────────────────────────────────────────────────────────┐
│  ✓ Repository Analysis                            42s   │
│  ✓ Threat Generation                              38s   │
│  ⟳ Attack Tree Generation          ██████████░░ 83%    │
│    🌳 Attack tree for threat 10 generated              │
│  ⟳ TTP Enrichment                  ████████░░░░ 66%    │
│    🤖 TTP mapping for threat 8 reviewed                │
│  ⟳ Mitigation Mapping              ████░░░░░░░░ 33%    │
│    🛡️ Mitigations for threat 4 generated               │
│  ○ Dashboard Generation                                │
└─────────────────────────────────────────────────────────┘
```

### Backend Changes

**`executor.py`** — When `parallel_pipeline` starts, immediately emit `stage_start` for all 3 stages. The poller then emits `stage_progress` events for each stage independently:

```python
async def _poll_parallel_progress():
    # On first poll with total > 0, emit all 3 stage_starts
    started = False
    
    while True:
        await asyncio.sleep(1)
        pp = get_parallel_progress()
        total = pp.get("total_threats", 0)
        if not total:
            continue
            
        if not started:
            for stage_name in ["Attack Tree Generation", "TTP Enrichment", "Mitigation Mapping"]:
                progress_callback(ProgressEvent(
                    event_type="stage_start",
                    stage=stage_name,
                    percentage=0,
                    message=f"Starting {stage_name}",
                ))
            started = True
        
        # Count per-substage completions across all threats
        tree_done = sum(1 for i in range(total) 
                       if _substage_complete(pp, i, "tree"))
        ttp_done = sum(1 for i in range(total) 
                      if _substage_complete(pp, i, "ttp"))
        mit_done = sum(1 for i in range(total) 
                      if _substage_complete(pp, i, "mitigation"))
        
        # Emit independent progress for each stage
        for stage, done in [
            ("Attack Tree Generation", tree_done),
            ("TTP Enrichment", ttp_done), 
            ("Mitigation Mapping", mit_done),
        ]:
            progress_callback(ProgressEvent(
                event_type="stage_progress",
                stage=stage,
                percentage=int(100 * done / total),
                message=f"{done}/{total} threats",
            ))
```

This requires enriching `_update_progress()` in `parallel.py` to track **which sub-stages each threat has completed** (not just current stage), or using the filesystem-based detection that already exists in the poller.

**`RunProgressPage.jsx`** — Support multiple stages being `in-progress` simultaneously. Currently the `stage_start` handler auto-completes earlier stages, which would need to be changed:

```javascript
case 'stage_start': {
    // DON'T auto-complete stages at lower indices — allow concurrent in-progress
    setStages((prev) => prev.map((s, i) =>
        i === stageIdx && s.status !== 'in-progress'
            ? { ...s, status: 'in-progress', progress: 0, startTime: ts }
            : s
    ));
    break;
}
```

Overall progress would weight the 3 parallel stages as their average:

```javascript
// Parallel stages contribute their average to overall progress
const parallelAvg = (stages[2].progress + stages[3].progress + stages[4].progress) / 3;
setOverallProgress(Math.round((2 + parallelAvg / 100) / 6 * 100));
```

### Frontend Changes

- `StageCard.jsx` — No changes needed; each stage already renders independently
- `RunProgressPage.jsx` — Modify `stage_start` to not auto-complete siblings; adjust overall progress calculation
- Consider adding a visual "parallel bracket" indicator (e.g., a left border or grouping line) to signal these stages run concurrently

### Pros
- **Keeps the 6-stage pipeline feel** — users still see the familiar breakdown of Tree → TTP → Mitigation
- **Shows true parallelism** — all 3 progress bars advance simultaneously, which is visually impressive
- **Independent timing** — each stage gets its own elapsed timer and completion timestamp
- **Most informative** — you can answer "how far along is TTP Enrichment?" directly

### Cons
- **Breaks the sequential mental model** — users expect stages to go one-after-another; seeing 3 active at once may confuse
- **Complex progress tracking** — need to track per-substage completion per-threat (currently only tracks current stage)
- **Overall progress is harder** — the 3 parallel stages need to be weighted as a group for the overall bar
- **Auto-complete logic gets tricky** — `stage_start` currently auto-completes earlier stages; need careful gating to only do this for non-parallel stages
- **Requires `parallel.py` changes** — need to track substage *completion* flags, not just current stage

### Estimated Effort: **Medium** (~4-6 hours)
- Backend: Enrich `_progress` tracking to record substage completions, rewrite poller for per-stage emission
- Frontend: Modify stage_start logic, adjust overall progress, optional visual grouping
- Tests: Update for concurrent stages, new progress calculations

---

## Option C: Grouped "Parallel Analysis" Parent with Nested Sub-Stages

### Concept

Add a **parent container stage** ("Parallel Analysis") that visually groups the 3 sub-stages. The parent shows overall parallel progress while the nested sub-stages show individual progress. This communicates both "these happen in parallel" and "here's each phase's status."

### UI Mockup

```
┌─────────────────────────────────────────────────────────┐
│  ✓ Repository Analysis                            42s   │
│  ✓ Threat Generation                              38s   │
│  ⟳ Parallel Analysis (5/12 threats)             1m 23s  │
│    ┌─────────────────────────────────────────────────┐   │
│    │ ████████████████████░░░░░░░  41%               │   │
│    ├─────────────────────────────────────────────────┤   │
│    │  ⟳ 🌳 Attack Trees        ██████████░░  83%   │   │
│    │  ⟳ 📐 TTP Enrichment      ████████░░░░  66%   │   │
│    │  ⟳ 🛡️ Mitigation Mapping   ████░░░░░░░░  33%   │   │
│    ├─────────────────────────────────────────────────┤   │
│    │ ✅ T1: Done   │ ⚡ T5: 🤖 TTP  │ ⏳ T9: Queued│   │
│    │ ✅ T2: Done   │ ⚡ T6: 🌳 Tree │ ⏳ T10:Queued│   │
│    │ ✅ T3: Done   │ ⚡ T7: 🌳 Tree │ ⏳ T11:Queued│   │
│    │ ✅ T4: Done   │ ⚡ T8: 🛡️ Mit  │ ⏳ T12:Queued│   │
│    │ ✅ T5: Done   │                │              │   │
│    └─────────────────────────────────────────────────┘   │
│  ○ Dashboard Generation                                 │
└─────────────────────────────────────────────────────────┘
```

### Backend Changes

**`executor.py`** — Emit a **single stage** (`"Parallel Analysis"`) but enrich the `details` payload with per-substage progress:

```python
# Count per-substage completions
tree_done = count_threats_past_stage(pp, "tree")
ttp_done = count_threats_past_stage(pp, "ttp") 
mit_done = count_threats_past_stage(pp, "mitigation")

progress_callback(ProgressEvent(
    event_type="stage_progress",
    stage="Parallel Analysis",
    percentage=int(100 * done / total),
    message=f"{done}/{total} threats complete",
    details={
        "workers": workers,
        "total": total,
        "completed": done,
        "substages": [
            {"name": "Attack Tree Generation", "icon": "🌳", "done": tree_done, "total": total},
            {"name": "TTP Enrichment", "icon": "📐", "done": ttp_done, "total": total},
            {"name": "Mitigation Mapping", "icon": "🛡️", "done": mit_done, "total": total},
        ],
    },
))
```

Similar to Option A, this requires enriching `parallel.py` to track substage completions.

**`RunProgressPage.jsx`** — 4 stages like Option A. The `details.substages` data is passed through to StageCard.

### Frontend Changes

**New `ParallelSubStages` component** (or enhance `StageCard`):

```jsx
// Inside StageCard, when substages are present:
{isInProgress && details?.substages && (
  <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
    {details.substages.map((sub) => (
      <div key={sub.name} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span>{sub.icon}</span>
        <span style={{ width: '160px', fontSize: '12px' }}>{sub.name}</span>
        <div style={{ flex: 1 }}>
          <ProgressBar value={Math.round(100 * sub.done / sub.total)} />
        </div>
        <span style={{ fontSize: '12px', minWidth: '50px' }}>
          {sub.done}/{sub.total}
        </span>
      </div>
    ))}
  </div>
)}
```

### Pros
- **Best of both worlds** — parent stage shows overall parallel progress; sub-stages show per-phase detail
- **Clear visual grouping** — obvious that these 3 phases are part of one parallel operation
- **Keeps sequential pipeline feel** — 4 top-level stages still flow linearly
- **Most informative** — shows overall progress, per-substage progress, AND per-threat worker grid
- **Elegant** — communicates the architecture naturally without requiring users to understand parallelism

### Cons
- **Most complex UI** — requires a new sub-stage rendering pattern in StageCard
- **Information dense** — might overwhelm users who just want to see "is it done yet?"
- **Backend enrichment needed** — same as Option B for per-substage counting
- **Wider StageCard** — more content inside a single stage card; may need scrolling or collapsible sections for many threats

### Estimated Effort: **Medium-Large** (~5-8 hours)
- Backend: Enrich progress details with substage counts, simplify stage transitions
- Frontend: New sub-stage progress bars in StageCard, 4-stage list, optional collapsible worker grid
- Tests: New substage rendering tests, updated stage counts

---

## Comparison Matrix

| Criteria | Option A: Single Stage | Option B: Concurrent | Option C: Grouped |
|---|---|---|---|
| **Accuracy** | ✅ Honest — it's one parallel phase | ✅ Shows true concurrency | ✅ Best — grouped + per-phase |
| **Simplicity** | ✅ Simplest (4 stages) | ⚠️ Moderate | ⚠️ Moderate |
| **Backend effort** | ✅ Small (simplify) | ⚠️ Medium (enrich tracking) | ⚠️ Medium (enrich tracking) |
| **Frontend effort** | ✅ Small (stage list + legend) | ⚠️ Medium (concurrent logic) | ⚠️ Medium-Large (new component) |
| **User experience** | ✅ Clean, focused | ⚠️ May confuse (3 active at once) | ✅ Most informative |
| **Granularity** | ⚠️ Per-threat only | ✅ Per-phase | ✅ Both per-phase AND per-threat |
| **Sequential mental model** | ✅ Preserved (4 linear stages) | ❌ Broken (3 concurrent) | ✅ Preserved (4 linear + nested) |
| **Progress monotonicity** | ✅ Always increases | ✅ Per-stage increases | ✅ Always increases |
| **Overall progress calc** | ✅ Simple (threats done / total) | ⚠️ Complex (weighted average) | ✅ Simple (threats done / total) |

---

## Recommendation

**Option A** is the pragmatic choice for immediate improvement — it's the least effort, removes confusing behavior, and the worker grid already provides per-threat detail. The backend actually gets *simpler*.

**Option C** is the gold-standard if we want maximum visibility — it preserves the familiar pipeline feel while honestly showing parallelism. It requires a new sub-stage rendering pattern but builds naturally on Option A's backend simplification.

A **phased approach** works well: ship Option A first (quick win), then enhance to Option C later by adding the sub-stage progress bars inside the single "Parallel Analysis" card.
