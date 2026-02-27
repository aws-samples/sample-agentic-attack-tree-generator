# Evaluation & Optimization with Langfuse

ThreatForest integrates with [Langfuse](https://langfuse.com) for tracing, SME review, and dataset export. This guide walks through the full evaluation pipeline — from connecting Langfuse to exporting scored datasets for prompt optimization.

---

## Prerequisites

- ThreatForest installed (`pipx install .` or `pip install .`)
- A Langfuse account with API keys (self-hosted or [cloud](https://cloud.langfuse.com))
- Sample applications or your own project to evaluate

---

## Step 1: Configure Langfuse

### Interactive Setup

```bash
threatforest config langfuse
```

The wizard prompts for your public key, secret key, and host URL.

### Direct Setup

```bash
threatforest config langfuse \
  --enable \
  --public-key pk-lf-xxxx \
  --secret-key sk-lf-xxxx \
  --host https://cloud.langfuse.com \
  --test
```

The `--test` flag verifies the connection.

### Disable Tracing

```bash
threatforest config langfuse --disable
```

When disabled, ThreatForest runs normally without any tracing overhead.

---

## Step 2: Register Score Definitions

ThreatForest defines 12 evaluation dimensions across three capabilities. Register them in Langfuse so SME reviewers see the correct scoring scales:

```bash
threatforest config langfuse --register-scores
```

This creates score configs in Langfuse for:

**Threat Statement Generation** (5 dimensions):

| Score Config Name | Description |
|---|---|
| `threat_overall_quality` | Holistic assessment of generated threats |
| `threat_relevance_to_context` | Match to application context |
| `threat_completeness` | Coverage of threat categories |
| `threat_technical_accuracy` | Technical correctness |
| `threat_hallucination_score` | Absence of fabricated content |

**Attack Tree Generation** (6 dimensions):

| Score Config Name | Description |
|---|---|
| `attack_tree_overall_quality` | Holistic assessment of the attack tree |
| `attack_tree_structural_quality` | Depth, branching, organization |
| `attack_tree_technical_realism` | Feasibility of attack techniques |
| `attack_tree_attack_path_logic` | Logical progression from access to impact |
| `attack_tree_completeness` | Coverage of attack vectors and phases |
| `attack_tree_actionability` | Usefulness for defenders |

**TTP Matching** (1 dimension):

| Score Config Name | Description |
|---|---|
| `ttp_mapping_quality` | Quality of MITRE ATT&CK technique mapping |

All dimensions use a 5-point categorical scale:

| Category | Value | Meaning |
|---|---|---|
| Excellent | 1.00 | Exceptional quality, no issues |
| Good | 0.75 | Above average, minor issues |
| Acceptable | 0.50 | Meets minimum requirements |
| Poor | 0.25 | Below expectations, significant issues |
| Unacceptable | 0.00 | Fails to meet requirements |

To sync with existing configs already in Langfuse (e.g., from a previous setup):

```bash
threatforest config langfuse --sync-scores
```

---

## Step 3: Run ThreatForest with Tracing

With Langfuse enabled, every ThreatForest run automatically produces traces with:

- Input context (technologies, architecture, deployment model)
- Agent outputs (threats, attack trees, TTP mappings)
- Generation metadata (model, latency, token counts)
- Automated structural metrics (node count, path count, depth, phase coverage)

### Using Sample Applications

ThreatForest ships with sample applications covering diverse domains:

```bash
# Healthcare Analytics (HIPAA, AWS, S3, Lambda, DynamoDB)
threatforest run --project-path sample-applications/hcls-example

# IoT Device Management (MQTT, Edge Computing, OTA)
threatforest run --project-path sample-applications/iot-device-management

# E-commerce Platform (Microservices, Payment APIs, PCI-DSS)
threatforest run --project-path sample-applications/ecommerce-platform

# GenAI Chatbot (Bedrock, RAG, Vector DB, AI Safety)
threatforest run --project-path sample-applications/genai-chatbot

# Connected Vehicle Platform (V2X, Telematics, OBD-II)
threatforest run --project-path sample-applications/vehicle-platform
```

### Using Your Own Project

```bash
threatforest run --project-path /path/to/your/project
```

After each run, traces appear in your Langfuse dashboard.

---

## Step 4: SME Review in Langfuse

Once traces are in Langfuse, you need to set up annotation queues so SMEs can systematically review and score outputs.

### Create Annotation Queues

In the Langfuse UI, create three queues — one per capability:

1. Go to your Langfuse project → **Annotation Queues** in the left sidebar
2. Click **+ New Queue** and create each of the following:

| Queue Name | Score Configs to Attach |
|---|---|
| `threatforest-threat-statements` | `threat_overall_quality`, `threat_relevance_to_context`, `threat_completeness`, `threat_technical_accuracy`, `threat_hallucination_score` |
| `threatforest-attack-trees` | `attack_tree_overall_quality`, `attack_tree_structural_quality`, `attack_tree_technical_realism`, `attack_tree_attack_path_logic`, `attack_tree_completeness`, `attack_tree_actionability` |
| `threatforest-ttp-matching` | `ttp_mapping_quality` |

When creating each queue, select the matching score configs from the dropdown — these were registered in [Step 2](#step-2-register-score-definitions).

### Add Traces to Queues

1. Go to **Traces** in the Langfuse sidebar
2. Filter by the relevant trace name or tag (e.g., `trace_type: attack_tree`)
3. Select the traces you want reviewed
4. Click **Add to Annotation Queue** and choose the matching queue

### Score Traces

SMEs open the annotation queue and work through each item:

1. Go to **Annotation Queues** → select a queue
2. For each trace, review the input context and generated output
3. Assign scores using the 5-point categorical scale (Excellent → Unacceptable)
4. Optionally add free-text feedback

!!! tip "Review Workflow"
    Focus on one queue at a time. Complete all threat statement reviews before moving to attack trees. This improves consistency across scores.

---

## Step 5: Export to Datasets

Export scored traces to Langfuse Datasets for evaluation analysis or prompt optimization:

### Export by Capability

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

### Export with Date Filters

```bash
threatforest export traces \
  --trace-type attack_tree \
  --start-date 2025-01-01 \
  --end-date 2025-01-31 \
  --dataset-name attack-trees-january
```

### Export Ground Truth Only

```bash
threatforest export traces \
  --ground-truth-only \
  --dataset-name ground-truth-v1
```

### Dry Run

Preview what would be exported without writing to Langfuse:

```bash
threatforest export traces \
  --trace-type attack_tree \
  --status reviewed \
  --dataset-name test \
  --dry-run
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

To establish a baseline evaluation across all sample domains:

```bash
# 1. Configure and test Langfuse
threatforest config langfuse --test

# 2. Register score definitions
threatforest config langfuse --register-scores

# 3. Run all sample applications
for domain in hcls-example iot-device-management ecommerce-platform genai-chatbot vehicle-platform; do
  threatforest run --project-path sample-applications/$domain
done

# 4. (Manual) SME review in Langfuse dashboard

# 5. Export reviewed traces to datasets
threatforest export traces --trace-type threat_statement --status reviewed -d baseline-threats-v1
threatforest export traces --trace-type attack_tree --status reviewed -d baseline-attack-trees-v1
threatforest export traces --trace-type ttp_matching --status reviewed -d baseline-ttp-v1
```

The exported datasets contain `input`/`expected_output` pairs structured for direct use with prompt optimization frameworks like DSPy.

---

## Resilient Tracing

ThreatForest's tracing is designed to never block your workflow:

- If Langfuse is unreachable, tracing silently falls back to no-op mode
- All Langfuse API errors are caught and logged without interrupting execution
- When Langfuse is disabled (`--disable`), there is zero tracing overhead
