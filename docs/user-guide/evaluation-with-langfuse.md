# Evaluation & Optimization with Langfuse

ThreatForest integrates with [Langfuse](https://langfuse.com) for tracing, SME review, and dataset export. This guide walks through the full evaluation pipeline — from connecting Langfuse to exporting scored datasets for prompt optimization.

---

## Prerequisites

- ThreatForest installed (`pipx install .` or `pip install .`)
- A Langfuse account with API keys (self-hosted or [cloud](https://cloud.langfuse.com))
- `strands-agents[otel]` installed (included in ThreatForest dependencies)
- Sample applications or your own project to evaluate

---

## Step 1: Configure Langfuse

### Interactive Setup (CLI)

```bash
threatforest config langfuse
```

The wizard prompts for your public key, secret key, and host URL. On successful connection, score definitions are automatically registered with Langfuse.

### Direct Setup

```bash
threatforest config langfuse \
  --enable \
  --public-key pk-lf-xxxx \
  --secret-key sk-lf-xxxx \
  --host https://cloud.langfuse.com \
  --test
```

The `--test` flag verifies the connection and auto-registers score configs.

### Console UI Setup

Navigate to the **Configure** page in the ThreatForest web console. The **Langfuse Tracing** section lets you:

- Toggle tracing on/off
- Enter your public key, secret key, and host
- Test the connection
- Save settings

### Disable Tracing

```bash
threatforest config langfuse --disable
```

When disabled, ThreatForest runs normally without any tracing overhead.

---

## Step 2: Score Definitions

Score definitions are automatically registered when you configure Langfuse (via CLI, wizard, or `--test`). You can also register them manually:

```bash
threatforest config langfuse --register-scores
```

ThreatForest defines **16 evaluation dimensions** across four capabilities:

### Threat Statement Generation (5 dimensions)

| Score Config Name | Description |
|---|---|
| `threat_overall_quality` | Holistic assessment of generated threats |
| `threat_relevance_to_context` | Match to application context |
| `threat_completeness` | Coverage of threat categories |
| `threat_technical_accuracy` | Technical correctness |
| `threat_hallucination_score` | Absence of fabricated content |

### Attack Tree Generation (6 dimensions)

| Score Config Name | Description |
|---|---|
| `attack_tree_overall_quality` | Holistic assessment of the attack tree |
| `attack_tree_structural_quality` | Depth, branching, organization |
| `attack_tree_technical_realism` | Feasibility of attack techniques |
| `attack_tree_attack_path_logic` | Logical progression from access to impact |
| `attack_tree_completeness` | Coverage of attack vectors and phases |
| `attack_tree_actionability` | Usefulness for defenders |

### TTP Matching (1 dimension)

| Score Config Name | Description |
|---|---|
| `ttp_mapping_quality` | Quality of MITRE ATT&CK technique mapping |

### Mitigation Quality (4 dimensions)

| Score Config Name | Description |
|---|---|
| `mitigation_actionability` | Whether the mitigation provides concrete, implementable steps |
| `mitigation_specificity` | How specific the mitigation is to the identified threat and tech stack |
| `mitigation_coverage` | Whether mitigations address all identified attack paths |
| `mitigation_technical_accuracy` | Correctness of recommended controls and configurations |

### Scoring Scale

All dimensions (except TTP) use a 5-point categorical scale:

| Category | Value | Meaning |
|---|---|---|
| Excellent | 1.00 | Exceptional quality, no issues |
| Good | 0.75 | Above average, minor issues |
| Acceptable | 0.50 | Meets minimum requirements |
| Poor | 0.25 | Below expectations, significant issues |
| Unacceptable | 0.00 | Fails to meet requirements |

TTP mapping uses a specialized scale replacing "Unacceptable" with "No Mapping".

To sync with existing configs already in Langfuse:

```bash
threatforest config langfuse --sync-scores
```

---

## Step 3: Run ThreatForest with Tracing

With Langfuse enabled, every ThreatForest run produces two types of traces:

### OTEL Traces (Automatic)

Full graph execution traces captured via OpenTelemetry, including:

- Every LLM call with input/output, token counts, and latency
- Tool invocations (file reads, structural analysis)
- Agent event loop cycles
- All traces share a session ID (e.g., `tf-a4162895b65c`) for grouping

These are the detailed engineering traces for debugging and performance analysis.

### Annotation Traces (Automatic)

Clean input/output pairs per subgraph, pushed via the Langfuse SDK for SME review:

| Trace Name | Input | Output | Tags |
|---|---|---|---|
| `scanner` | Task description | `scanner_context.json` | `scanner`, `annotation` |
| `threat-generation` | Scanner context | `threats.json` | `threat`, `annotation` |
| `attack-tree-pipeline` | Threats | Attack trees + TTP mappings + mitigations | `attack-tree`, `ttp`, `mitigation`, `annotation` |

These traces are designed for annotation queues — filter by the `annotation` tag in Langfuse.

### Using Sample Applications

```bash
# S3 Multi-Tenant SaaS (S3, Access Points, Object Lambda, KMS)
threatforest run --project-path sample-applications/s3

# Healthcare Analytics (HIPAA, AWS, S3, Lambda, DynamoDB)
threatforest run --project-path sample-applications/hcls-example

# IoT Device Management (MQTT, Edge Computing, OTA)
threatforest run --project-path sample-applications/iot-device-management

# Connected Vehicle Platform (V2X, Telematics, OBD-II)
threatforest run --project-path sample-applications/vehicle-platform
```

### Using Your Own Project

```bash
threatforest run --project-path /path/to/your/project
```

After each run, traces appear in your Langfuse dashboard under the session ID.

---

## Step 4: SME Review in Langfuse

### Create Annotation Queues

In the Langfuse UI, create queues for each capability:

1. Go to your Langfuse project → **Annotation Queues**
2. Click **+ New Queue** and create:

| Queue Name | Score Configs to Attach |
|---|---|
| `threatforest-threat-statements` | `threat_overall_quality`, `threat_relevance_to_context`, `threat_completeness`, `threat_technical_accuracy`, `threat_hallucination_score` |
| `threatforest-attack-trees` | `attack_tree_overall_quality`, `attack_tree_structural_quality`, `attack_tree_technical_realism`, `attack_tree_attack_path_logic`, `attack_tree_completeness`, `attack_tree_actionability` |
| `threatforest-ttp-matching` | `ttp_mapping_quality` |
| `threatforest-mitigations` | `mitigation_actionability`, `mitigation_specificity`, `mitigation_coverage`, `mitigation_technical_accuracy` |

### Add Traces to Queues

1. Go to **Traces** → filter by tag `annotation`
2. Select traces and click **Add to Annotation Queue**
3. Choose the matching queue based on the trace name

### Score Traces

SMEs open the annotation queue and work through each item:

1. Review the input context and generated output
2. Assign scores using the categorical scale
3. Optionally add free-text feedback

!!! tip "Review Workflow"
    Focus on one queue at a time. Complete all threat statement reviews before moving to attack trees. This improves consistency across scores.

---

## Step 5: Export to Datasets

Export scored traces to Langfuse Datasets for evaluation analysis or prompt optimization:

```bash
# Reviewed threat statement traces
threatforest export traces \
  --trace-type threat_statement \
  --status reviewed \
  --dataset-name threat-statements-v1

# Reviewed attack tree traces
threatforest export traces \
  --trace-type attack_tree \
  --status reviewed \
  --dataset-name attack-trees-v1

# Reviewed TTP matching traces
threatforest export traces \
  --trace-type ttp_matching \
  --status reviewed \
  --dataset-name ttp-matching-v1
```

### Export Options Reference

| Option | Description |
|---|---|
| `--trace-type`, `-t` | Filter: `threat_statement`, `attack_tree`, `ttp_matching` |
| `--status`, `-s` | Filter: `pending_review`, `reviewed` |
| `--start-date` | ISO date lower bound (e.g., `2025-01-01`) |
| `--end-date` | ISO date upper bound |
| `--ground-truth-only` | Only export ground truth candidates |
| `--dataset-name`, `-d` | Target Langfuse Dataset name (required) |
| `--dataset-description` | Description for new datasets |
| `--dry-run` | Preview without exporting |

---

## Full Baseline Workflow

```bash
# 1. Configure Langfuse (auto-registers score configs)
threatforest config langfuse --test

# 2. Run sample applications
for domain in s3 hcls-example iot-device-management vehicle-platform; do
  threatforest run --project-path sample-applications/$domain
done

# 3. (Manual) SME review in Langfuse annotation queues

# 4. Export reviewed traces to datasets
threatforest export traces --trace-type threat_statement --status reviewed -d baseline-threats-v1
threatforest export traces --trace-type attack_tree --status reviewed -d baseline-attack-trees-v1
threatforest export traces --trace-type ttp_matching --status reviewed -d baseline-ttp-v1
```

---

## Resilient Tracing

ThreatForest's tracing is designed to never block your workflow:

- If Langfuse is unreachable, tracing silently falls back to no-op mode
- All Langfuse API errors are caught and logged without interrupting execution
- When Langfuse is disabled (`--disable`), there is zero tracing overhead
- OTEL spans are flushed before the process exits to ensure delivery
