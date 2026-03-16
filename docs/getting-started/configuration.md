# Configuration

ThreatForest stores configuration in `.threatforest/config.yaml` relative to the directory you launch it from. Secrets such as API keys go in `.threatforest/.env`.

!!! info "Config file location"
    The config file is **global to your ThreatForest installation**, not per-project. It lives in `.threatforest/config.yaml` inside whichever directory you run `threatforest` from (typically the ThreatForest repo root or your home directory).

---

## Quick Setup

The primary way to configure ThreatForest is through the **Configure** page in the web console (`http://localhost:8000/configure`). Changes made here are written directly to `config.yaml` and take effect on the next run — no restart required.

For CLI-based setup:

```bash
threatforest config init
```

This creates `.threatforest/config.yaml` with sensible defaults and opens a wizard to set your provider credentials.

---

## CLI Commands

| Command | Description |
|---|---|
| `threatforest config init` | Create config file (first-time setup) |
| `threatforest config show` | Print current configuration |
| `threatforest config edit` | Edit config interactively |
| `threatforest config set <key> <value>` | Set a single value |
| `threatforest config path` | Show path to active config file |

**Example:**

```bash
threatforest config set bedrock.model_id us.anthropic.claude-sonnet-4-5-v1:0
threatforest config set bedrock.region_name us-east-1
```

---

## LLM Providers

=== "AWS Bedrock (Recommended)"

    Fully tested and supported. Requires an AWS profile with:

    - `bedrock:InvokeModel`
    - `bedrock:InvokeModelWithResponseStream`

    ```yaml
    bedrock:
      model_id: us.anthropic.claude-sonnet-4-5-v1:0
      region_name: us-east-1
      profile_name: your-aws-profile   # optional
    ```

=== "Anthropic"

    Direct Anthropic API access. Experimental.

    ```yaml
    anthropic:
      model_id: claude-sonnet-4-5
      api_key: sk-ant-...   # or set ANTHROPIC_API_KEY in .env
    ```

=== "OpenAI"

    Experimental.

    ```yaml
    openai:
      model_id: gpt-4o
      api_key: sk-...   # or set OPENAI_API_KEY in .env
    ```

=== "Google Gemini"

    Experimental.

    ```yaml
    gemini:
      model_id: gemini-1.5-pro
      api_key: ...   # or set GOOGLE_API_KEY in .env
    ```

=== "Ollama (local)"

    Fully local, no data sent externally. Experimental.

    ```yaml
    ollama:
      model_id: llama3.1
      base_url: http://localhost:11434
    ```

=== "AWS SageMaker"

    For self-hosted models on SageMaker endpoints. Experimental.

    ```yaml
    sagemaker:
      endpoint_name: my-endpoint
      region_name: us-east-1
    ```

---

## Embeddings Settings

ThreatForest uses `basel/ATTACK-BERT` by default to map attack steps to MITRE ATT&CK techniques.

```yaml
embeddings:
  model: basel/ATTACK-BERT
  ttc_threshold: 0.3   # minimum similarity score (0.0-1.0)
```

!!! tip
    Lower `ttc_threshold` returns more (but weaker) matches. Raise it to 0.4-0.5 for stricter mapping.

---

## Secrets (.env)

API keys and tracing credentials go in `.threatforest/.env` — never in `config.yaml`.

```bash
# .threatforest/.env
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
LANGFUSE_ENABLED=true
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
```

---

## Langfuse Tracing (Optional)

Langfuse provides observability — traces, SME review queues, and dataset export.

```bash
# Interactive setup
threatforest config langfuse

# Or set directly
threatforest config langfuse --enable --public-key pk-lf-... --secret-key sk-lf-... --test
```

See [Evaluation & Optimization](../user-guide/evaluation-with-langfuse.md) for the full workflow.
