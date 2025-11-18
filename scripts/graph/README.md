# AWS Attack Framework (AAF) Knowledge Graph

## Overview

This directory contains tools for converting the AWS Attack Framework (AAF) STIX threat intelligence data into a Neptune graph database with semantic search capabilities. The graph enables powerful threat intelligence queries, relationship traversal, and similarity-based searches using embeddings.

## Directory Structure

```
graph/
├── stix_to_neptune.py      # Main conversion script
├── demo.ipynb               # Interactive Jupyter notebook for queries
├── graph.html               # Web-based graph visualization
├── data/                    # Data files (graph summaries, etc.)
└── output/                  # Generated CSV files for Neptune import
```

## Graph Schema

### Node Types (276 total)

- **Technique** (229 nodes) - Attack techniques from AAF/ATT&CK
  - Properties: `name`, `description`, `aws_services`, `aws_api_events`, `tactics`, `aliases`
  - **Special Feature**: Includes embeddings for semantic similarity search
  
- **Tactic** (12 nodes) - High-level attack objectives
  - Examples: Collection, Privilege Escalation, Initial Access, Defense Evasion
  
- **ThreatActor** (1 node) - Known threat actor groups
  - Example: OST (Offensive Security Team)
  
- **Mitigation** (7 nodes) - Security controls and countermeasures
  - Examples: User Account Management, Software Configuration, Audit
  
- **DataComponent** (11 nodes) - Detection data sources
  - Examples: Network Traffic Content, Firewall Disable, Cloud Storage Modification
  
- **DataSource** (8 nodes) - Detection mechanisms
  - Examples: Network Traffic, Firewall, Cloud Storage

- **Identity** (2 nodes) - Organizations
- **Infrastructure** (1 node) - Cloud platforms
- **Marking-Definition** (4 nodes) - TLP classifications

### Edge Types (210 total)

- **SUBTECHNIQUE_OF** (137) - Parent-child technique relationships
- **USES** (43) - Threat actors using techniques
- **DETECTS** (17) - Data components detecting techniques
- **MITIGATES** (12) - Mitigations for techniques
- **TARGETS** (1) - Techniques targeting infrastructure

## Key Features

### 1. Semantic Search with Embeddings

Technique nodes include vector embeddings generated from their descriptions, enabling similarity-based searches:

```python
# Find techniques similar to a query
query_embedding = neptune_manager.embedding_ops.get_embedding(
    "Perform an attack to avoid possible detection of tools and activities"
)

neptune_query = f"""
CALL neptune.algo.vectors.topKByEmbedding({query_embedding})
YIELD node, score
RETURN node, score
LIMIT 10
"""

results = neptune_manager.query_ops.execute_query(neptune_query)
```

### 2. Relationship Traversal

Navigate the graph to understand attack paths and relationships:

```gremlin
// Find all techniques used by OST threat actor
MATCH (actor:ThreatActor {name: 'OST'})-[:USES]->(tech:Technique)
RETURN tech.name, tech.description

// Find sub-techniques of a parent technique
MATCH (parent:Technique)<-[:SUBTECHNIQUE_OF]-(child:Technique)
WHERE parent.external_ids CONTAINS 'T1190'
RETURN parent.name, child.name

// Find mitigations for a technique
MATCH (mitigation:Mitigation)-[:MITIGATES]->(tech:Technique)
WHERE tech.name = 'Password Spraying'
RETURN mitigation.name, mitigation.description
```

### 3. Interactive Visualization

Open `graph.html` in a browser to explore the graph visually:
- Hover over nodes to see detailed information
- Click nodes to view properties in side panel
- Interactive layout with physics simulation
- Color-coded by node type

## Usage

### Running the Conversion Script

```bash
cd threatforest-agentic-application/threatforest-strands/scripts/graph
python3 stix_to_neptune.py
```

**What it does:**
1. Loads ttc-aaf.json STIX bundle
2. Parses 486 STIX objects into nodes and edges
3. Generates embeddings for Technique nodes (using Neptune)
4. Uploads to Neptune graph database
5. Creates a new graph called "threatforest-graph"

**Configuration** (in stix_to_neptune.py):
```python
STIX_FILE = "data/threat-intelligence/ttc-aaf.json"
S3_BUCKET = "threatforest-neptune"
GRAPH_ID = "g-f7i4wf2pc5"
```

### Using the Jupyter Notebook

```bash
jupyter notebook demo.ipynb
```

**Available cells:**
1. **Setup** - Connect to Neptune graph
2. **Basic Query** - Explore subtechnique relationships
3. **Semantic Search** - Find similar techniques using embeddings
4. **Visualization** - Generate interactive graph views

### Example Queries

#### 1. Find techniques by AWS service
```gremlin
MATCH (t:Technique)
WHERE t.aws_services CONTAINS 'Amazon S3'
RETURN t.name, t.aws_services, t.tactics
```

#### 2. Find techniques by tactic
```gremlin
MATCH (t:Technique)
WHERE t.tactics CONTAINS 'credential-access'
RETURN t.name, t.description
LIMIT 10
```

#### 3. Find detection methods for a technique
```gremlin
MATCH (dc:DataComponent)-[:DETECTS]->(t:Technique {name: 'Disable or Modify Cloud Firewall'})
RETURN dc.name, dc.description
```

#### 4. Trace threat actor TTPs
```gremlin
MATCH (actor:ThreatActor {name: 'OST'})-[:USES]->(tech:Technique)
RETURN tech.name, tech.tactics, tech.aws_services
ORDER BY tech.name
```

#### 5. Find technique relationships
```gremlin
MATCH path = (parent:Technique)<-[:SUBTECHNIQUE_OF*1..2]-(child:Technique)
WHERE parent.name = 'Brute Force'
RETURN path
```

## AWS-Specific Metadata

Each Technique node includes:

- **`aws_services`** - AWS services targeted (e.g., "Amazon S3", "Amazon EC2")
- **`aws_api_events`** - Specific API calls (e.g., "s3:DeleteObject", "ec2:RunInstances")
- **`tactics`** - MITRE ATT&CK tactics (e.g., "initial-access", "persistence")
- **`external_ids`** - Technique IDs (e.g., "T1190", "AT1026")

Example node:
```json
{
  "name": "Disable or Modify Cloud Firewall",
  "stix_type": "attack-pattern",
  "aws_services": "Amazon Elastic Compute Cloud (EC2),AWS Firewall Manager,AWS Network Firewall",
  "aws_api_events": "ec2:AuthorizeSecurityGroupIngress",
  "tactics": "defense-evasion",
  "external_ids": "T1562.007"
}
```

## Visualization Features

The `graph.html` file provides:

### Interactive Elements
- **Hover tooltips** - Rich HTML tooltips with node/edge details
- **Click interaction** - Side panel with full property listing
- **Physics simulation** - Automatic graph layout with Barnes-Hut algorithm
- **Navigation** - Pan, zoom, and drag nodes
- **Connection metrics** - View incoming/outgoing edge counts

### Visual Encoding
- **Node size** - Proportional to number of connections (degree)
- **Node color** - All nodes use consistent teal color (#95e1d3)
- **Edge color** - Gray edges, highlighted in purple on hover

## Semantic Search Use Cases

The embedding functionality enables powerful semantic queries:

### Example 1: Find Defense Evasion Techniques
```python
query = "techniques to hide malicious activity and avoid detection"
embedding = neptune_manager.embedding_ops.get_embedding(query)

results = neptune_manager.query_ops.execute_query(f"""
    CALL neptune.algo.vectors.topKByEmbedding({embedding})
    YIELD node, score
    WHERE node:Technique
    RETURN node.name, node.description, score
    LIMIT 5
""")
```

### Example 2: Find Similar Techniques
```python
# Find techniques similar to "Password Spraying"
reference_node = neptune_manager.query_ops.execute_query("""
    MATCH (t:Technique {name: 'Password Spraying'})
    RETURN t
""")[0]

similar = neptune_manager.embedding_ops.find_similar_nodes(
    reference_node, 
    limit=10
)
```

## Data Pipeline

```
STIX Bundle (ttc-aaf.json)
    ↓
STIXParser
    ↓
Nodes + Edges
    ↓
Embedding Generation (Technique nodes only)
    ↓
CSV Generation
    ↓
S3 Upload
    ↓
Neptune Bulk Load
    ↓
Knowledge Graph (ready for queries)
```

## Graph Statistics

- **Total Objects**: 486 STIX objects processed
- **Nodes Created**: 276 (after filtering)
- **Edges Created**: 210 relationships
- **Embeddings**: Generated for 229 Technique nodes
- **Data Source**: AWS Attack Framework (AAF) - internal AWS threat intelligence

## Advanced Queries

### Multi-hop Traversal
```gremlin
// Find techniques 2-3 hops from a tactic
MATCH path = (tactic:Tactic {name: 'Initial Access'})-[:SUBTECHNIQUE_OF*2..3]-(tech:Technique)
RETURN path
LIMIT 20
```

### Aggregate Analysis
```gremlin
// Count techniques by tactic
MATCH (t:Technique)
UNWIND split(t.tactics, ',') AS tactic
RETURN tactic, count(t) as technique_count
ORDER BY technique_count DESC
```

### Detection Coverage Analysis
```gremlin
// Find techniques without detection methods
MATCH (t:Technique)
WHERE NOT (t)<-[:DETECTS]-()
RETURN t.name, t.tactics, t.aws_services
```

## Requirements

- Python 3.8+
- boto3
- neptune-graph-manager
- Neptune Analytics graph (not Neptune Database)
- S3 bucket for intermediate storage
- AWS credentials with appropriate permissions

## Troubleshooting

### Issue: "UnprocessableException" during bulk load
**Solution**: Retry the script - this is a transient Neptune error

### Issue: Missing embeddings
**Solution**: Ensure Neptune supports embedding operations for your graph type

### Issue: S3 Access Denied
**Solution**: Verify S3 bucket permissions and AWS credentials

## Future Enhancements

1. **Incremental Updates** - Support updating only changed techniques
2. **Multi-source Integration** - Combine multiple STIX bundles
3. **Custom Visualizations** - ATT&CK Navigator-style heatmaps
4. **Query Templates** - Pre-built queries for common threat hunting scenarios
5. **Export Functionality** - Export sub-graphs for sharing

## Related Documentation

- [AAF Techniques Wiki](https://w.amazon.com/bin/view/AWS/Teams/GlobalServicesSecurity/TDIR/TRIAD/AAF/)
- [Neptune Graph Manager](https://github.com/aws/neptune-graph-manager)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/)
