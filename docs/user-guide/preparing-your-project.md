# Preparing Your Project

ThreatForest works by pointing it at a directory — the agents then intelligently decide what to read and analyze. You don't need a perfect project structure; just point it at your repo.

## What ThreatForest Can Read

ThreatForest accepts a broad range of input types:

- **Documentation** — README files, architecture docs, design specs, security policies, API references
- **Architecture diagrams** — PNG, JPG, PDF, Mermaid (`.mmd`), Draw.io (`.drawio`), PlantUML (`.puml`)
- **Threat models** — ThreatComposer (`.tc.json`), custom JSON/YAML threat model files
- **Infrastructure as Code** — Terraform, CloudFormation, CDK, Pulumi, Kubernetes manifests
- **Code** — Source files that describe how components interact or handle sensitive data

The scanner agent explores your repository, determines which files are most relevant to security analysis, and passes that context to the downstream threat modeling agents. You don't need to configure what gets read — the agents figure it out.

## Minimum Requirements

ThreatForest needs at least one of:

- A `README.md` describing your application
- An architecture diagram
- Any documentation describing the system

The more context you provide, the more accurate the threat model will be — but a single README is enough to get started.

## Project Structure Examples

### Minimal

```
my-project/
├── README.md
```

### Typical

```
my-project/
├── README.md
├── ARCHITECTURE.md
├── diagrams/
│   └── data-flow.png
└── infra/
    └── main.tf
```

### Comprehensive

```
my-project/
├── README.md
├── ARCHITECTURE.md
├── SECURITY.md
├── MyApp.tc.json
├── docs/
│   ├── api-spec.md
│   └── deployment-guide.md
├── diagrams/
│   ├── data-flow.mmd
│   └── network-topology.pdf
└── infra/
    ├── main.tf
    └── kubernetes/
```

## Tips for Better Results

- **Describe trust boundaries** — note where data crosses network zones, authentication points, and external integrations
- **Name technologies** — mention databases, cloud services, auth providers, and messaging systems
- **Include IaC** — Terraform and CloudFormation files give ThreatForest precise visibility into your infrastructure configuration
- **Add data flow context** — describe what sensitive data your system handles and how it moves

## Next Steps

- **[Running ThreatForest](running-threatforest.md)** — Learn to execute analysis
- **[Understanding Your Results](understanding-results.md)** — Explore outputs
- **[How ThreatForest Works](../how-it-works/index.md)** — Technical deep dive
