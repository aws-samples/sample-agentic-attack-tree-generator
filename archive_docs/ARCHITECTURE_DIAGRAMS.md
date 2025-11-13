# ThreatForest Architecture Diagrams

This document contains comprehensive Mermaid diagrams that illustrate the ThreatForest application architecture, workflow, and component interactions.

## Diagram Overview

### 1. Application Architecture (`threatforest_application_architecture.mmd`)

**Purpose**: Shows the complete system architecture including all layers and components.

**Key Elements**:
- **User Interface Layer**: React Ink CLI and Web interfaces
- **Strands Agent Orchestration**: Main orchestrator agent with state management and progress tracking
- **Tool Layer**: Specialized tools for each capability (setup, analysis, generation, etc.)
- **Core Infrastructure**: Bedrock clients, file discovery, rate limiting, error handling
- **TTC Mapping System**: Embedding-based technique matching and STIX-based mitigation enrichment
- **External Services**: AWS Bedrock, SentenceTransformer models, STIX data
- **File System**: Project files, outputs, state persistence, and caching

**Color Coding**:
- 🔵 Blue: Strands Agent components
- 🟣 Purple: Specialized tools
- 🟢 Green: Core infrastructure
- 🟠 Orange: External services
- 🔴 Pink: Data storage and files

### 2. Workflow Sequence (`threatforest_workflow_diagram.mmd`)

**Purpose**: Illustrates the step-by-step execution flow of the ThreatForest analysis process.

**Workflow Stages**:
1. **Setup & Validation**: AWS/Bedrock connectivity verification
2. **Context Analysis**: Project file discovery and categorization
3. **Information Extraction**: AI-powered threat analysis of project context
4. **Attack Tree Generation**: Mermaid diagram creation for high-severity threats
5. **TTC Mapping**: Technique mapping using embedding similarity
6. **Summary & Report**: Final analysis report and data export generation

**Key Features**:
- State management with checkpointing and resume capability
- Progress tracking with real-time UI updates
- Error handling and retry mechanisms
- Parallel processing where applicable

### 3. Component Interactions (`threatforest_component_interactions.mmd`)

**Purpose**: Details how different system components interact and data flows between them.

**Component Categories**:
- **Input Sources**: Project files, threat models, documentation, architecture diagrams
- **Strands Agent Framework**: Tool registry, state management, progress tracking, workflow orchestration
- **Specialized Tools**: Analysis tools (setup, context, extraction) and generation tools (trees, mapping, summary)
- **AI & Processing**: AWS Bedrock models, embedding systems, TTC framework
- **Output Generation**: Attack trees, reports, and data exports

## Architecture Highlights

### Strands Agent Framework

ThreatForest is built on the **Strands agent framework**, which provides:

- **Agent Orchestration**: The `ThreatForestOrchestrator` coordinates all workflow stages
- **Tool-Based Architecture**: Each capability is encapsulated as a reusable tool
- **State Management**: Persistent state with checkpointing and resume functionality
- **Progress Tracking**: Real-time progress events for UI updates
- **Error Handling**: Robust retry mechanisms and graceful degradation

### Key Design Patterns

1. **Agent-Tool Pattern**: The orchestrator agent delegates specific tasks to specialized tools
2. **Pipeline Architecture**: Sequential stages with dependency management
3. **State Persistence**: Workflow state is saved at each stage for resume capability
4. **Event-Driven Progress**: Progress events enable real-time UI updates
5. **Embedding-Based Matching**: Semantic similarity for technique mapping
6. **Rate-Limited AI Calls**: Intelligent throttling to respect API limits

### Technology Stack

- **Agent Framework**: Custom Strands implementation
- **AI Models**: AWS Bedrock (Claude, Titan, Llama)
- **Embeddings**: SentenceTransformer models
- **Security Framework**: MITRE ATT&CK TTC with STIX data
- **Output Format**: Mermaid diagrams, Markdown reports, JSON exports
- **UI**: React Ink for CLI, Web interface support

## Usage

To view these diagrams:

1. **In VS Code**: Install the Mermaid Preview extension
2. **Online**: Copy diagram content to [Mermaid Live Editor](https://mermaid.live/)
3. **In Documentation**: Many platforms (GitHub, GitLab, etc.) render Mermaid natively

## Files

- `threatforest_application_architecture.mmd` - Complete system architecture
- `threatforest_workflow_diagram.mmd` - Workflow sequence diagram  
- `threatforest_component_interactions.mmd` - Component interaction flow
- `ARCHITECTURE_DIAGRAMS.md` - This documentation file

These diagrams provide a comprehensive view of how ThreatForest leverages the Strands agent framework to orchestrate complex AI-driven threat modeling workflows.