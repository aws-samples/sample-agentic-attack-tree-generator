# Release Notes

## Upgrading

To upgrade ThreatForest to the latest version:

**Using uv:**
```bash
uv tool upgrade threatforest
```

**Using pipx:**
```bash
pipx upgrade threatforest
```

**Using pip:**
```bash
pip install --upgrade threatforest
```

---

## Version 0.4.0

**Release Date:** May 20, 2026

### Mitigation tracking

- **Editable mitigation statuses** — Each mitigation now carries an explicit status (Already implemented / In progress / Accepted risk / Not relevant / Won't do) with a required comment. Status is shown read-only on each per-threat table and edited centrally on the deduplicated Mitigations tab.
- **Implementation guidance refresh** — Numbered guidance now renders as a real ordered list (the LLM's `1) ...` style was previously collapsing into one paragraph), and every mitigation row gains a Copy as Markdown button so guidance can be pasted straight into Notion / Linear / Jira.
- **Accurate export totals** — The mitigations PDF / CSV exports now match the on-screen count exactly, include the full implementation guidance per mitigation, and carry the override status + comment columns.

### Threat-model report bundle

- **Export `.tfreport` bundles** — A new export format produces a self-contained zip of state files, business context, and run metadata. The Customise Export modal lets users pick which sections to include (PDF / CSV / JSON / .tfreport) and override the filename.
- **Import `.tfreport` bundles** — Recipients without source-code access can drop a `.tfreport` into `.threatforest/imports/` (or upload via the new Import button); the server materialises a read-only Application + Version, and the UI badges it as "Imported from <name>".

### Business context

- **CIA priority ranking** — The single "main CIA risk" field is replaced with a length-3 ranking of confidentiality / integrity / availability via a drag-to-reorder UI in the create-application wizard and the AppOverviewPage editor. The threat agent uses the ranking to bias generated threats toward the highest-priority objective. Legacy single-value records migrate transparently.
- **Highly confidential** data-sensitivity tier added.

### Run metadata

- **Run metadata sidecar** — Every run now captures model id, frameworks selected, ATT&CK version, started_at, completed_at, and duration in a new `run_metadata.json` sidecar. The summary page renders this in a collapsible section at the bottom, with model ids and framework keys resolved to friendly names.

### UX polish

- **Onboarding banner** — A one-time "Where do I start?" banner on the threat-model summary page orients first-time developers and security reviewers.
- **Click an attack-step badge** in the per-threat MitigationsTable to focus its node on the attack-tree viewer, with the right-side panel opening automatically.
- **Threat-review primary action** now follows user intent — when there are pending edits, "Apply changes" is the primary green button; otherwise "Continue" reclaims the primary slot.
- **Wiz technique links** — Wiz framework slugs (e.g. `refresh-token-compromise`) now build correct URLs across the UI; previously they fell through to a 404 on `attack.mitre.org`.
- **TTP frameworks default to all-ticked** on the New Run wizard. The previous preselection logic compared regulatory frameworks against TTP keys, leaving every checkbox unticked.

---

## Version 1.0.0

**Release Date:** TBD

### What's New

- **Web Console UI** — Browser-based interface for running analyses, viewing results, and managing configuration without touching the CLI
- **Langfuse tracing** — Optional observability integration for tracing agent runs, reviewing outputs, and building evaluation datasets
- **Agent verifiers** — Each pipeline stage now includes a verifier that checks output quality and automatically retries if the result is invalid, improving accuracy and consistency across runs

---

## Version 0.0.1

**Release Date:** December 4, 2024

### Features

- Initial release of ThreatForest
- AI-powered threat modeling and attack tree generation
- MITRE ATT&CK framework integration
- Support for multiple LLM providers (AWS Bedrock, Anthropic, OpenAI, Gemini, Ollama)
- Autonomous repository analysis using the Strands framework
- Multi-stage pipeline with state management
