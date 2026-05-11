# Running ThreatForest

ThreatForest has two interfaces: a **web console** (default) and a **terminal wizard** (`--tui`). Both run the same analysis pipeline.

---

## Web Console (Default)

```bash
threatforest
```

Opens `http://localhost:8000` in your browser automatically.

**Options:**

```bash
threatforest --port 8001          # use a different port
threatforest --host 0.0.0.0       # bind to all interfaces
```

### Pages

#### Home
Lists your applications as cards and surfaces any paused runs that can be resumed. Click **Add application** to register a new one — name, project path, and business context are captured up front.

#### Application Overview
Shows the application's threat models (one per run) plus its business context and project path. From here you can:

- **New run** — start an analysis for this application
- Edit the **project path** when the repository moves or is renamed; on-disk run history stays attached
- Open a past version, or **delete** a version you no longer need

#### New Run
Confirms the application's project path and business context, then starts the pipeline. The application's saved context flows straight into the scanner.

#### Run Progress
Live view of the pipeline as it executes — shows each stage completing in real time:

1. **Scanner Agent** — explores repo structure
2. **Threat Agent** — identifies threats
3. **Parallel Pipeline** — attack trees, TTP mapping, mitigations (all threats run concurrently)
4. **Report Generator** — compiles final outputs

#### Threat Model Summary / Version Detail
The summary lists all threats for a run with severity and category. Click a threat to open the version detail view — attack tree, MITRE ATT&CK mappings, and mitigations.

#### Configure
Set your LLM provider credentials and Langfuse tracing without touching the config file. See [Configuration](../getting-started/configuration.md).

---

## Terminal Mode

```bash
threatforest --tui
```

An interactive wizard in the terminal. Useful for headless environments or scripted workflows.

The wizard guides you through:

1. **Mode selection** — Full analysis, or update credentials/model settings
2. **Project path** — Path to the project to analyze
3. **Threat file** — Optionally provide an existing threat file
4. **Confirmation** — Review settings before starting

Progress is shown inline as each pipeline stage completes.

---

## Pipeline Stages

Regardless of interface, every run executes the same 4-stage pipeline:

| Stage | What Happens |
|---|---|
| **Scanner** | Explores repo; identifies tech stack, cloud provider, services, auth mechanisms |
| **Threat** | Reads scanner context; produces structured threat list |
| **Parallel Pipeline** | For each threat concurrently: generates attack tree, maps TTPs, adds mitigations |
| **Report** | Deterministic compilation into dashboard, report, and JSON export |

Each stage has a verifier — if the output is invalid, the stage retries automatically.

---

## When Analysis Completes

Results are written to `.threatforest/output/` inside your project:

- `threat_model_report.md` — executive summary
- `threatforest_data.json` — structured JSON export

To explore the interactive visualization — attack trees, MITRE ATT&CK mappings, and mitigations — open the run in the web console dashboard.

[→ Understanding Results](understanding-results.md)

---

## Handling Errors

ThreatForest retries failed stages automatically. For persistent issues, check the [FAQ Troubleshooting section](../faq.md#troubleshooting).
