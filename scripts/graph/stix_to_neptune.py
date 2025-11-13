#!/usr/bin/env python3
"""
STIX to Neptune Graph Converter

Converts STIX 2.1 bundles (like ttc-aaf.json) to Neptune graph format.
Handles attack-patterns, relationships, tactics, mitigations, and other STIX objects.
"""

import json
import os
from ast import literal_eval
from pathlib import Path
from typing import Any, Dict, List, Tuple

from boto3 import Session
from dotenv import load_dotenv
from neptune_graph_manager import GraphBuilder, NeptuneGraphManager
from neptune_graph_manager.types import Edge, Node, NodeArray

# Load environment
load_dotenv()

# Configuration
STIX_FILE = Path(__file__).parents[1] / "data/threat-intelligence/ttc-aaf.json"
S3_BUCKET = "threatforest-neptune"
S3_PREFIX = "stix-aaf-data"
GRAPH_ID = "g-f7i4wf2pc5"  # Your Neptune graph ID

# Initialize AWS session
session = Session(**literal_eval(os.getenv("SESSION_PARAMS", "{}")))

# Initialize Neptune manager
print(f"🔗 Connecting to Neptune graph: {GRAPH_ID}")
neptune_manager = NeptuneGraphManager(session=session, graph_id=GRAPH_ID)


class STIXParser:
    """Parser for STIX 2.1 bundles to convert to Neptune graph format"""

    # Define which STIX types we want to convert to nodes
    NODE_TYPES = {
        "attack-pattern",
        "x-mitre-tactic",
        "intrusion-set",
        "course-of-action",
        "x-mitre-data-source",
        "x-mitre-data-component",
        "identity",
        "infrastructure",
        "marking-definition",
        "x-mitre-matrix",
    }

    # Relationship types we want to create edges for
    EDGE_TYPES = {"subtechnique-of", "uses", "mitigates", "detects", "targets"}

    def __init__(self):
        self.node_cache = {}  # Cache nodes to avoid duplicates

    def parse_bundle(self, bundle_data: Dict[str, Any]) -> Tuple[List[Node], List[Edge]]:
        """Parse a STIX bundle and return nodes and edges"""

        if bundle_data.get("type") != "bundle":
            raise ValueError("Input must be a STIX bundle")

        objects = bundle_data.get("objects", [])
        print(f"📦 Processing {len(objects)} STIX objects...")

        nodes: List[Node] = []
        edges: List[Edge] = []
        relationships = []  # Store relationships to process after nodes

        # First pass: create nodes
        for obj in objects:
            obj_type = obj.get("type")

            if obj_type == "relationship":
                # Store relationships for second pass
                relationships.append(obj)
            elif obj_type in self.NODE_TYPES:
                node = self._create_node(obj)
                if node:
                    nodes.append(node)
                    self.node_cache[obj["id"]] = node

        print(f"  ✓ Created {len(nodes)} nodes")

        # Second pass: create edges from relationships
        for rel in relationships:
            edge = self._create_edge(rel)
            if edge:
                edges.append(edge)

        print(f"  ✓ Created {len(edges)} edges")

        nodes_wo_embeddings = NodeArray([n for n in nodes if n.label != "Technique"])
        nodes = NodeArray(nodes).filter_by_label("Technique").generate_embeddings(neptune_manager=neptune_manager, properties="description")
        nodes.extend(nodes_wo_embeddings)
        return nodes, edges

    def _create_node(self, obj: Dict[str, Any]) -> Node:
        """Create a Neptune node from a STIX object"""

        obj_id = obj.get("id")
        obj_type = obj.get("type")
        name = obj.get("name", obj_id)

        # Create node label
        if obj_type == "attack-pattern":
            label = f"Technique"
        elif obj_type == "x-mitre-tactic":
            label = f"Tactic"
        elif obj_type == "intrusion-set":
            label = f"ThreatActor"
        elif obj_type == "course-of-action":
            label = f"Mitigation"
        elif obj_type == "x-mitre-data-source":
            label = f"DataSource"
        elif obj_type == "x-mitre-data-component":
            label = f"DataComponent"
        elif obj_type == "identity":
            label = f"Identity"
        elif obj_type == "infrastructure":
            label = f"Infrastructure"
        else:
            label = obj_type.replace("x-mitre-", "").title()

        # Extract key properties
        properties = {
            "stix_id": obj_id,
            "stix_type": obj_type,
            "name": name,
            "created": obj.get("created"),
            "modified": obj.get("modified"),
        }

        # Add description if available
        if "description" in obj:
            properties["description"] = obj.get("description")

        # Add external references
        if "external_references" in obj:
            ext_refs = obj.get("external_references", [])
            if ext_refs:
                properties["external_ids"] = ",".join(
                    [ref.get("external_id", "") for ref in ext_refs if ref.get("external_id")]
                )
                properties["urls"] = ",".join(
                    [ref.get("url", "") for ref in ext_refs if ref.get("url")]
                )

        # Add AWS-specific properties for attack patterns
        if obj_type == "attack-pattern":
            if "x_aaf_aws_services" in obj:
                properties["aws_services"] = ",".join(obj.get("x_aaf_aws_services", []))
            if "x_aaf_aws_api_events" in obj:
                properties["aws_api_events"] = ",".join(obj.get("x_aaf_aws_api_events", []))
            if "kill_chain_phases" in obj:
                phases = [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])]
                properties["tactics"] = ",".join(phases)

        # Add aliases
        if "aliases" in obj:
            properties["aliases"] = ",".join(obj.get("aliases", []))

        # Filter out None values and empty strings - Neptune doesn't accept them
        properties = {k: v for k, v in properties.items() if v is not None and v != ""}

        return Node(obj_id, label, properties)

    def _create_edge(self, rel: Dict[str, Any]) -> Edge:
        """Create a Neptune edge from a STIX relationship"""

        rel_type = rel.get("relationship_type")
        source_ref = rel.get("source_ref")
        target_ref = rel.get("target_ref")

        # Skip if we don't have both source and target nodes
        if source_ref not in self.node_cache or target_ref not in self.node_cache:
            return None

        # Only create edges for relationship types we care about
        if rel_type not in self.EDGE_TYPES:
            return None

        source_node = self.node_cache[source_ref]
        target_node = self.node_cache[target_ref]

        # Create edge label
        label = rel_type.upper().replace("-", "_")

        # Create edge with relationship metadata
        edge_properties = {
            "relationship_id": rel.get("id"),
            "created": rel.get("created"),
            "modified": rel.get("modified"),
            "description": rel.get("description", "") if rel.get("description") else "",
        }

        # Filter out None values and empty strings - Neptune doesn't accept them
        edge_properties = {k: v for k, v in edge_properties.items() if v is not None and v != ""}

        edge = Edge(label=label, source=source_node, target=target_node, properties=edge_properties)

        return edge


def stix_data_generator(stix_file: Path, parser: STIXParser):
    """Generator to yield STIX data in batches"""

    print(f"📂 Loading STIX bundle from {stix_file}...")

    with open(stix_file, "r") as f:
        bundle_data = json.load(f)

    nodes, edges = parser.parse_bundle(bundle_data)

    print(f"  ✓ {len(nodes):,} nodes, {len(edges):,} edges")

    # Yield as a single batch
    yield {"nodes": nodes, "edges": edges}


def main():
    """Main execution function"""

    # Get graph summary
    # print("\n📊 Current graph summary:")
    # summary = neptune_manager.get_summary()
    # print(f"  Nodes: {summary.get('numNodes', 0):,}")
    # print(f"  Edges: {summary.get('numEdges', 0):,}")

    # Initialize parser and builder
    parser = STIXParser()
    builder = GraphBuilder(
        s3_bucket=S3_BUCKET,
        s3_prefix=S3_PREFIX,
        create_new_graph=True,
        graph_memory=64,
        verbose=True,
        # neptune_manager=neptune_manager,
        graph_name="threatforest-graph"
    )
    builder._set_session(session)

    print("\n🚀 Building graph from STIX data...\n")

    # Process STIX data
    for result in builder.process_batches(stix_data_generator(STIX_FILE, parser)):
        info = result[0]
        print(
            f"✓ Batch {info['batch_count']}: {info['nodes_count']:,} nodes, {info['edges_count']:,} edges\n"
        )

    # # Get updated summary
    # print("\n📊 Updated graph summary:")
    # summary = neptune_manager.get_summary()
    # print(f"  Nodes: {summary.get('numNodes', 0):,}")
    # print(f"  Edges: {summary.get('numEdges', 0):,}")

    print("\n✅ Done!")


if __name__ == "__main__":
    main()
