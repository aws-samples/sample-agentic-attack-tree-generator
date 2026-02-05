"""
Metrics Calculator for ThreatForest Attack Trees

This module provides automated metrics calculation for attack trees, including:
- Structural metrics (node_count, path_count, max_depth, branching_factor)
- Phase coverage calculation for attack phase detection
- MITRE ATT&CK technique extraction

These metrics are used for automated evaluation of attack tree quality
and are captured as part of the tracing infrastructure.

Requirements:
- 5.2: THE Tracing_Module SHALL capture automated_metrics including node_count,
       path_count, max_depth, branching_factor, syntax_valid
- 5.4: THE Tracing_Module SHALL calculate phase_coverage_score based on
       detected attack phases
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any


# =============================================================================
# Attack Phases Definition
# =============================================================================
# These are the standard MITRE ATT&CK phases/tactics that we detect in attack trees.
# Based on the MITRE ATT&CK Enterprise framework.

ATTACK_PHASES: Set[str] = {
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact",
}

# Mapping of common keywords/phrases to attack phases for detection
PHASE_KEYWORDS: Dict[str, List[str]] = {
    "reconnaissance": [
        "reconnaissance", "recon", "scanning", "enumeration", "enumerate",
        "discovery", "information gathering", "footprinting", "osint",
        "identify", "probe", "survey", "research"
    ],
    "initial_access": [
        "initial access", "initial_access", "entry point", "compromise",
        "phishing", "exploit public", "drive-by", "supply chain",
        "valid accounts", "external remote", "trusted relationship"
    ],
    "execution": [
        "execution", "execute", "run", "command", "script", "powershell",
        "cmd", "shell", "payload", "malware", "code execution"
    ],
    "persistence": [
        "persistence", "persist", "maintain access", "backdoor",
        "scheduled task", "registry", "startup", "boot", "implant"
    ],
    "privilege_escalation": [
        "privilege escalation", "privilege_escalation", "escalate",
        "elevate", "admin", "root", "sudo", "uac bypass", "token"
    ],
    "defense_evasion": [
        "defense evasion", "defense_evasion", "evasion", "evade",
        "bypass", "disable", "obfuscate", "hide", "masquerade", "stealth"
    ],
    "credential_access": [
        "credential access", "credential_access", "credentials",
        "password", "hash", "kerberos", "ticket", "dump", "keylog",
        "brute force", "credential stuffing"
    ],
    "discovery": [
        "discovery", "discover", "enumerate", "list", "query",
        "network scan", "system info", "account discovery"
    ],
    "lateral_movement": [
        "lateral movement", "lateral_movement", "lateral", "pivot",
        "move", "spread", "remote service", "pass the hash", "rdp", "ssh"
    ],
    "collection": [
        "collection", "collect", "gather", "data", "archive",
        "clipboard", "screen capture", "keylog", "email collection"
    ],
    "exfiltration": [
        "exfiltration", "exfiltrate", "exfil", "transfer", "upload",
        "send data", "data theft", "steal data", "extract"
    ],
    "impact": [
        "impact", "damage", "destroy", "encrypt", "ransomware",
        "denial of service", "dos", "defacement", "wipe", "disrupt"
    ],
}

# MITRE ATT&CK technique ID pattern (e.g., T1059, T1059.001)
# Uses word boundary to avoid matching partial numbers
MITRE_TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


# =============================================================================
# Data Classes for Metrics Results
# =============================================================================

@dataclass
class StructuralMetrics:
    """
    Structural metrics for an attack tree.
    
    Attributes:
        node_count: Total number of nodes in the tree
        path_count: Number of unique attack paths from root to leaves
        max_depth: Maximum depth of the tree (root = depth 0)
        branching_factor: Average number of children per non-leaf node
        syntax_valid: Whether the tree has valid syntax
    """
    node_count: int = 0
    path_count: int = 0
    max_depth: int = 0
    branching_factor: float = 0.0
    syntax_valid: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "node_count": self.node_count,
            "path_count": self.path_count,
            "max_depth": self.max_depth,
            "branching_factor": round(self.branching_factor, 2),
            "syntax_valid": self.syntax_valid,
        }


@dataclass
class PhaseCoverage:
    """
    Phase coverage metrics for an attack tree.
    
    Attributes:
        phases_detected: Set of attack phases detected in the tree
        expected_phases: Set of expected attack phases
        coverage_score: Ratio of detected phases to expected phases (0.0 to 1.0)
    """
    phases_detected: Set[str] = field(default_factory=set)
    expected_phases: Set[str] = field(default_factory=lambda: ATTACK_PHASES.copy())
    coverage_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "phases_detected": sorted(list(self.phases_detected)),
            "expected_phases": sorted(list(self.expected_phases)),
            "coverage_score": round(self.coverage_score, 4),
        }


@dataclass
class TechniqueDetection:
    """
    MITRE ATT&CK technique detection results.
    
    Attributes:
        mitre_techniques_found: List of MITRE technique IDs found
        technique_count: Number of unique techniques found
    """
    mitre_techniques_found: List[str] = field(default_factory=list)
    technique_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "mitre_techniques_found": self.mitre_techniques_found,
            "technique_count": self.technique_count,
        }


# =============================================================================
# Tree Parsing Helpers
# =============================================================================

def _parse_tree_structure(content: str) -> Dict[str, Any]:
    """
    Parse attack tree markdown content into a tree structure.
    
    This function parses markdown-formatted attack trees where:
    - Headings (# ## ###) represent tree levels
    - List items (- *) represent nodes at the same level
    - Indentation indicates parent-child relationships
    
    Args:
        content: The attack tree content in markdown format
        
    Returns:
        Dictionary with tree structure information:
        - nodes: List of all nodes
        - edges: List of parent-child relationships
        - depths: Dictionary mapping node index to depth
    """
    if not content or not content.strip():
        return {"nodes": [], "edges": [], "depths": {}}
    
    lines = content.strip().split("\n")
    nodes: List[str] = []
    edges: List[tuple] = []
    depths: Dict[int, int] = {}
    
    # Stack to track parent nodes at each depth level
    parent_stack: List[int] = []  # Stack of (node_index, depth)
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        
        # Determine depth based on heading level or indentation
        depth = 0
        node_text = stripped
        
        # Check for markdown headings
        if stripped.startswith("#"):
            heading_match = re.match(r"^(#+)\s*(.+)$", stripped)
            if heading_match:
                depth = len(heading_match.group(1)) - 1  # # = depth 0
                node_text = heading_match.group(2).strip()
        # Check for list items
        elif stripped.startswith(("-", "*", "+")):
            # Count leading whitespace for indentation
            leading_spaces = len(line) - len(line.lstrip())
            depth = leading_spaces // 2 + 1  # Base depth 1 for list items
            node_text = re.sub(r"^[-*+]\s*", "", stripped)
        else:
            # Regular text, treat as continuation or skip
            continue
        
        if not node_text:
            continue
        
        # Add node
        node_index = len(nodes)
        nodes.append(node_text)
        depths[node_index] = depth
        
        # Find parent and create edge
        while parent_stack and parent_stack[-1][1] >= depth:
            parent_stack.pop()
        
        if parent_stack:
            parent_index = parent_stack[-1][0]
            edges.append((parent_index, node_index))
        
        parent_stack.append((node_index, depth))
    
    return {"nodes": nodes, "edges": edges, "depths": depths}


def _count_paths(edges: List[tuple], node_count: int) -> int:
    """
    Count the number of unique paths from root to leaf nodes.
    
    A path is a sequence of nodes from the root (node with no parent)
    to a leaf (node with no children).
    
    Args:
        edges: List of (parent, child) tuples
        node_count: Total number of nodes
        
    Returns:
        Number of unique paths
    """
    if node_count == 0:
        return 0
    
    if node_count == 1:
        return 1
    
    # Build adjacency list
    children: Dict[int, List[int]] = {i: [] for i in range(node_count)}
    has_parent: Set[int] = set()
    
    for parent, child in edges:
        children[parent].append(child)
        has_parent.add(child)
    
    # Find root nodes (nodes without parents)
    roots = [i for i in range(node_count) if i not in has_parent]
    
    if not roots:
        # If no clear root, assume node 0 is root
        roots = [0]
    
    # Find leaf nodes (nodes without children)
    leaves = {i for i in range(node_count) if not children[i]}
    
    if not leaves:
        # If no leaves, all nodes are leaves
        return len(roots)
    
    # Count paths using DFS
    def count_paths_from(node: int) -> int:
        if node in leaves:
            return 1
        
        total = 0
        for child in children[node]:
            total += count_paths_from(child)
        
        return max(total, 1)  # At least 1 path if node exists
    
    total_paths = sum(count_paths_from(root) for root in roots)
    return max(total_paths, 1)


def _calculate_branching_factor(edges: List[tuple], node_count: int) -> float:
    """
    Calculate the average branching factor of the tree.
    
    Branching factor is the average number of children per non-leaf node.
    
    Args:
        edges: List of (parent, child) tuples
        node_count: Total number of nodes
        
    Returns:
        Average branching factor (0.0 if no non-leaf nodes)
    """
    if node_count <= 1 or not edges:
        return 0.0
    
    # Count children per node
    children_count: Dict[int, int] = {i: 0 for i in range(node_count)}
    
    for parent, child in edges:
        children_count[parent] += 1
    
    # Find non-leaf nodes (nodes with at least one child)
    non_leaf_nodes = [i for i in range(node_count) if children_count[i] > 0]
    
    if not non_leaf_nodes:
        return 0.0
    
    total_children = sum(children_count[i] for i in non_leaf_nodes)
    return total_children / len(non_leaf_nodes)


# =============================================================================
# Main Metrics Functions
# =============================================================================

def calculate_structural_metrics(content: str) -> Dict[str, Any]:
    """
    Calculate structural metrics for an attack tree.
    
    This function analyzes the structure of an attack tree and returns
    metrics including node count, path count, maximum depth, and
    branching factor.
    
    Args:
        content: The attack tree content in markdown format
        
    Returns:
        Dictionary containing structural metrics:
        - node_count: Total number of nodes
        - path_count: Number of unique attack paths
        - max_depth: Maximum depth of the tree
        - branching_factor: Average children per non-leaf node
        - syntax_valid: Whether the tree has valid syntax
        
    Example:
        >>> content = '''
        ... # Root Attack
        ... ## Step 1
        ... - Sub-step 1.1
        ... - Sub-step 1.2
        ... ## Step 2
        ... '''
        >>> metrics = calculate_structural_metrics(content)
        >>> metrics["node_count"]
        5
    """
    if not content or not content.strip():
        return StructuralMetrics(syntax_valid=False).to_dict()
    
    try:
        tree = _parse_tree_structure(content)
        nodes = tree["nodes"]
        edges = tree["edges"]
        depths = tree["depths"]
        
        node_count = len(nodes)
        
        if node_count == 0:
            return StructuralMetrics(syntax_valid=False).to_dict()
        
        max_depth = max(depths.values()) if depths else 0
        path_count = _count_paths(edges, node_count)
        branching_factor = _calculate_branching_factor(edges, node_count)
        
        metrics = StructuralMetrics(
            node_count=node_count,
            path_count=path_count,
            max_depth=max_depth,
            branching_factor=branching_factor,
            syntax_valid=True,
        )
        
        return metrics.to_dict()
        
    except Exception:
        # If parsing fails, return invalid syntax
        return StructuralMetrics(syntax_valid=False).to_dict()


def calculate_phase_coverage(
    content: str,
    expected_phases: Optional[Set[str]] = None
) -> Dict[str, Any]:
    """
    Calculate attack phase coverage for an attack tree.
    
    This function detects which attack phases are present in the attack tree
    content and calculates a coverage score based on the ratio of detected
    phases to expected phases.
    
    The coverage score is calculated as:
        coverage_score = len(detected ∩ expected) / len(expected)
    
    Args:
        content: The attack tree content in markdown format
        expected_phases: Set of expected attack phases. If None, uses
                        the default ATTACK_PHASES set.
        
    Returns:
        Dictionary containing phase coverage metrics:
        - phases_detected: List of detected attack phases
        - expected_phases: List of expected attack phases
        - coverage_score: Ratio of detected to expected phases (0.0 to 1.0)
        
    Example:
        >>> content = '''
        ... # Reconnaissance
        ... - Scan network
        ... # Initial Access
        ... - Phishing attack
        ... '''
        >>> coverage = calculate_phase_coverage(content)
        >>> "reconnaissance" in coverage["phases_detected"]
        True
    """
    if expected_phases is None:
        expected_phases = ATTACK_PHASES.copy()
    
    if not expected_phases:
        return PhaseCoverage(
            phases_detected=set(),
            expected_phases=set(),
            coverage_score=0.0
        ).to_dict()
    
    if not content or not content.strip():
        return PhaseCoverage(
            phases_detected=set(),
            expected_phases=expected_phases,
            coverage_score=0.0
        ).to_dict()
    
    # Normalize content for matching
    content_lower = content.lower()
    
    # Detect phases based on keywords
    detected_phases: Set[str] = set()
    
    for phase, keywords in PHASE_KEYWORDS.items():
        if phase not in expected_phases:
            continue
        
        for keyword in keywords:
            if keyword.lower() in content_lower:
                detected_phases.add(phase)
                break
    
    # Calculate coverage score
    intersection = detected_phases & expected_phases
    coverage_score = len(intersection) / len(expected_phases) if expected_phases else 0.0
    
    result = PhaseCoverage(
        phases_detected=detected_phases,
        expected_phases=expected_phases,
        coverage_score=coverage_score,
    )
    
    return result.to_dict()


def detect_mitre_techniques(content: str) -> Dict[str, Any]:
    """
    Detect MITRE ATT&CK technique IDs in attack tree content.
    
    This function searches for MITRE ATT&CK technique IDs in the format
    T#### or T####.### (e.g., T1059, T1059.001) within the attack tree
    content.
    
    Args:
        content: The attack tree content in markdown format
        
    Returns:
        Dictionary containing technique detection results:
        - mitre_techniques_found: List of unique technique IDs found
        - technique_count: Number of unique techniques found
        
    Example:
        >>> content = '''
        ... # Attack Tree
        ... - Execute PowerShell (T1059.001)
        ... - Credential Dumping (T1003)
        ... '''
        >>> techniques = detect_mitre_techniques(content)
        >>> "T1059.001" in techniques["mitre_techniques_found"]
        True
    """
    if not content or not content.strip():
        return TechniqueDetection().to_dict()
    
    # Find all MITRE technique IDs
    matches = MITRE_TECHNIQUE_PATTERN.findall(content)
    
    # Remove duplicates while preserving order
    seen: Set[str] = set()
    unique_techniques: List[str] = []
    
    for technique in matches:
        if technique not in seen:
            seen.add(technique)
            unique_techniques.append(technique)
    
    result = TechniqueDetection(
        mitre_techniques_found=unique_techniques,
        technique_count=len(unique_techniques),
    )
    
    return result.to_dict()


def calculate_automated_metrics(content: str) -> Dict[str, Any]:
    """
    Calculate all automated metrics for an attack tree.
    
    This is a convenience function that combines structural metrics,
    phase coverage, and technique detection into a single result.
    
    Args:
        content: The attack tree content in markdown format
        
    Returns:
        Dictionary containing all automated metrics:
        - structural: Structural metrics (node_count, path_count, etc.)
        - phase_coverage: Phase coverage metrics
        - technique_detection: MITRE technique detection results
        
    Example:
        >>> content = '''
        ... # Reconnaissance (T1595)
        ... - Scan network
        ... # Initial Access (T1190)
        ... - Exploit vulnerability
        ... '''
        >>> metrics = calculate_automated_metrics(content)
        >>> metrics["structural"]["node_count"]
        4
    """
    return {
        "structural": calculate_structural_metrics(content),
        "phase_coverage": calculate_phase_coverage(content),
        "technique_detection": detect_mitre_techniques(content),
    }
