#!/usr/bin/env python3
"""
Unit Tests for Metrics Calculator

This module contains unit tests for the metrics calculator functions
in the ThreatForest tracing module.

Tests cover:
- calculate_structural_metrics() for attack tree structure analysis
- calculate_phase_coverage() for attack phase detection
- detect_mitre_techniques() for MITRE ATT&CK technique extraction
"""

import sys
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from threatforest.tracing.metrics import (
    ATTACK_PHASES,
    PHASE_KEYWORDS,
    calculate_automated_metrics,
    calculate_phase_coverage,
    calculate_structural_metrics,
    detect_mitre_techniques,
)


# =============================================================================
# Test calculate_structural_metrics()
# =============================================================================

class TestCalculateStructuralMetrics:
    """Tests for calculate_structural_metrics() function."""
    
    def test_empty_content_returns_invalid_syntax(self):
        """Empty content should return syntax_valid=False."""
        result = calculate_structural_metrics("")
        assert result["syntax_valid"] is False
        assert result["node_count"] == 0
    
    def test_none_content_returns_invalid_syntax(self):
        """None content should return syntax_valid=False."""
        result = calculate_structural_metrics(None)
        assert result["syntax_valid"] is False
    
    def test_whitespace_only_returns_invalid_syntax(self):
        """Whitespace-only content should return syntax_valid=False."""
        result = calculate_structural_metrics("   \n\t\n   ")
        assert result["syntax_valid"] is False
    
    def test_single_heading_node(self):
        """Single heading should count as one node."""
        content = "# Root Attack"
        result = calculate_structural_metrics(content)
        
        assert result["syntax_valid"] is True
        assert result["node_count"] == 1
        assert result["max_depth"] == 0
        assert result["path_count"] == 1
    
    def test_multiple_headings_at_same_level(self):
        """Multiple headings at same level should be counted."""
        content = """# Attack 1
# Attack 2
# Attack 3"""
        result = calculate_structural_metrics(content)
        
        assert result["syntax_valid"] is True
        assert result["node_count"] == 3
    
    def test_nested_headings(self):
        """Nested headings should create proper tree structure."""
        content = """# Root
## Child 1
## Child 2
### Grandchild"""
        result = calculate_structural_metrics(content)
        
        assert result["syntax_valid"] is True
        assert result["node_count"] == 4
        assert result["max_depth"] == 2  # ### is depth 2
    
    def test_list_items_counted_as_nodes(self):
        """List items should be counted as nodes."""
        content = """# Root
- Step 1
- Step 2
- Step 3"""
        result = calculate_structural_metrics(content)
        
        assert result["syntax_valid"] is True
        assert result["node_count"] == 4
    
    def test_nested_list_items(self):
        """Nested list items should increase depth."""
        content = """# Root
- Step 1
  - Sub-step 1.1
  - Sub-step 1.2
- Step 2"""
        result = calculate_structural_metrics(content)
        
        assert result["syntax_valid"] is True
        assert result["node_count"] == 5
        assert result["max_depth"] >= 2
    
    def test_branching_factor_calculation(self):
        """Branching factor should be average children per non-leaf."""
        content = """# Root
## Child 1
## Child 2"""
        result = calculate_structural_metrics(content)
        
        assert result["syntax_valid"] is True
        # Root has 2 children, so branching factor = 2.0
        assert result["branching_factor"] == 2.0
    
    def test_path_count_single_path(self):
        """Single linear path should count as 1."""
        content = """# Root
## Step 1
### Step 2"""
        result = calculate_structural_metrics(content)
        
        assert result["path_count"] == 1
    
    def test_path_count_multiple_paths(self):
        """Multiple branches should create multiple paths."""
        content = """# Root
## Branch 1
### Leaf 1
## Branch 2
### Leaf 2"""
        result = calculate_structural_metrics(content)
        
        assert result["path_count"] >= 2
    
    def test_complex_tree_structure(self):
        """Complex tree should have correct metrics."""
        content = """# Attack Goal
## Reconnaissance
- Scan network
- Enumerate services
## Initial Access
- Phishing
  - Spear phishing
  - Mass phishing
- Exploit vulnerability
## Execution
- Run payload"""
        result = calculate_structural_metrics(content)
        
        assert result["syntax_valid"] is True
        assert result["node_count"] >= 10
        assert result["max_depth"] >= 2
        assert result["path_count"] >= 1
    
    def test_returns_dict_format(self):
        """Result should be a dictionary with expected keys."""
        content = "# Test"
        result = calculate_structural_metrics(content)
        
        assert isinstance(result, dict)
        assert "node_count" in result
        assert "path_count" in result
        assert "max_depth" in result
        assert "branching_factor" in result
        assert "syntax_valid" in result


# =============================================================================
# Test calculate_phase_coverage()
# =============================================================================

class TestCalculatePhaseCoverage:
    """Tests for calculate_phase_coverage() function."""
    
    def test_empty_content_returns_zero_coverage(self):
        """Empty content should return zero coverage."""
        result = calculate_phase_coverage("")
        
        assert result["coverage_score"] == 0.0
        assert len(result["phases_detected"]) == 0
    
    def test_none_content_returns_zero_coverage(self):
        """None content should return zero coverage."""
        result = calculate_phase_coverage(None)
        
        assert result["coverage_score"] == 0.0
    
    def test_single_phase_detected(self):
        """Single phase keyword should be detected."""
        content = "# Reconnaissance\n- Scan network"
        result = calculate_phase_coverage(content)
        
        assert "reconnaissance" in result["phases_detected"]
        assert result["coverage_score"] > 0.0
    
    def test_multiple_phases_detected(self):
        """Multiple phase keywords should be detected."""
        content = """# Attack Tree
## Reconnaissance
- Scan network
## Initial Access
- Phishing attack
## Execution
- Run malware"""
        result = calculate_phase_coverage(content)
        
        assert "reconnaissance" in result["phases_detected"]
        assert "initial_access" in result["phases_detected"]
        assert "execution" in result["phases_detected"]
    
    def test_coverage_score_calculation(self):
        """Coverage score should be detected/expected ratio."""
        # Use a custom expected set with 4 phases
        expected = {"reconnaissance", "initial_access", "execution", "persistence"}
        
        # Content with 2 of the 4 phases
        content = "Reconnaissance and execution steps"
        result = calculate_phase_coverage(content, expected)
        
        # 2 out of 4 = 0.5
        assert result["coverage_score"] == 0.5
    
    def test_full_coverage(self):
        """All phases detected should give 1.0 coverage."""
        expected = {"reconnaissance", "execution"}
        content = "Reconnaissance phase followed by execution"
        result = calculate_phase_coverage(content, expected)
        
        assert result["coverage_score"] == 1.0
    
    def test_case_insensitive_detection(self):
        """Phase detection should be case insensitive."""
        content = "RECONNAISSANCE and EXECUTION"
        result = calculate_phase_coverage(content)
        
        assert "reconnaissance" in result["phases_detected"]
        assert "execution" in result["phases_detected"]
    
    def test_keyword_variations_detected(self):
        """Various keyword forms should be detected."""
        # Test "recon" as variation of reconnaissance
        content = "Perform recon on target"
        result = calculate_phase_coverage(content)
        
        assert "reconnaissance" in result["phases_detected"]
    
    def test_credential_access_detection(self):
        """Credential access phase should be detected."""
        content = "Dump credentials from memory"
        result = calculate_phase_coverage(content)
        
        assert "credential_access" in result["phases_detected"]
    
    def test_lateral_movement_detection(self):
        """Lateral movement phase should be detected."""
        content = "Pivot to other systems using lateral movement"
        result = calculate_phase_coverage(content)
        
        assert "lateral_movement" in result["phases_detected"]
    
    def test_exfiltration_detection(self):
        """Exfiltration phase should be detected."""
        content = "Exfiltrate data to external server"
        result = calculate_phase_coverage(content)
        
        assert "exfiltration" in result["phases_detected"]
    
    def test_impact_detection(self):
        """Impact phase should be detected."""
        content = "Deploy ransomware for maximum impact"
        result = calculate_phase_coverage(content)
        
        assert "impact" in result["phases_detected"]
    
    def test_custom_expected_phases(self):
        """Custom expected phases should be used."""
        expected = {"reconnaissance", "execution"}
        content = "Reconnaissance and persistence"
        result = calculate_phase_coverage(content, expected)
        
        # Only reconnaissance is in expected set
        assert result["expected_phases"] == sorted(list(expected))
        assert "reconnaissance" in result["phases_detected"]
        # persistence is detected but not in expected
        assert result["coverage_score"] == 0.5
    
    def test_empty_expected_phases(self):
        """Empty expected phases should return zero coverage."""
        result = calculate_phase_coverage("Some content", set())
        
        assert result["coverage_score"] == 0.0
    
    def test_returns_dict_format(self):
        """Result should be a dictionary with expected keys."""
        result = calculate_phase_coverage("Test content")
        
        assert isinstance(result, dict)
        assert "phases_detected" in result
        assert "expected_phases" in result
        assert "coverage_score" in result
    
    def test_default_expected_phases(self):
        """Default expected phases should be ATTACK_PHASES."""
        result = calculate_phase_coverage("Test")
        
        assert set(result["expected_phases"]) == ATTACK_PHASES


# =============================================================================
# Test detect_mitre_techniques()
# =============================================================================

class TestDetectMitreTechniques:
    """Tests for detect_mitre_techniques() function."""
    
    def test_empty_content_returns_empty_list(self):
        """Empty content should return empty technique list."""
        result = detect_mitre_techniques("")
        
        assert result["mitre_techniques_found"] == []
        assert result["technique_count"] == 0
    
    def test_none_content_returns_empty_list(self):
        """None content should return empty technique list."""
        result = detect_mitre_techniques(None)
        
        assert result["mitre_techniques_found"] == []
    
    def test_single_technique_detected(self):
        """Single technique ID should be detected."""
        content = "Execute PowerShell (T1059)"
        result = detect_mitre_techniques(content)
        
        assert "T1059" in result["mitre_techniques_found"]
        assert result["technique_count"] == 1
    
    def test_subtechnique_detected(self):
        """Sub-technique ID (T####.###) should be detected."""
        content = "PowerShell execution (T1059.001)"
        result = detect_mitre_techniques(content)
        
        assert "T1059.001" in result["mitre_techniques_found"]
        assert result["technique_count"] == 1
    
    def test_multiple_techniques_detected(self):
        """Multiple technique IDs should be detected."""
        content = """
        - Execute PowerShell (T1059.001)
        - Credential Dumping (T1003)
        - Lateral Movement (T1021)
        """
        result = detect_mitre_techniques(content)
        
        assert "T1059.001" in result["mitre_techniques_found"]
        assert "T1003" in result["mitre_techniques_found"]
        assert "T1021" in result["mitre_techniques_found"]
        assert result["technique_count"] == 3
    
    def test_duplicate_techniques_deduplicated(self):
        """Duplicate technique IDs should be deduplicated."""
        content = "T1059 and T1059 and T1059"
        result = detect_mitre_techniques(content)
        
        assert result["mitre_techniques_found"] == ["T1059"]
        assert result["technique_count"] == 1
    
    def test_order_preserved(self):
        """Order of first occurrence should be preserved."""
        content = "T1003 then T1059 then T1021"
        result = detect_mitre_techniques(content)
        
        assert result["mitre_techniques_found"] == ["T1003", "T1059", "T1021"]
    
    def test_technique_in_url_detected(self):
        """Technique IDs in URLs should be detected."""
        content = "See https://attack.mitre.org/techniques/T1059/001/"
        result = detect_mitre_techniques(content)
        
        assert "T1059" in result["mitre_techniques_found"]
    
    def test_technique_in_markdown_link(self):
        """Technique IDs in markdown links should be detected."""
        content = "[T1059.001](https://attack.mitre.org/techniques/T1059/001/)"
        result = detect_mitre_techniques(content)
        
        assert "T1059.001" in result["mitre_techniques_found"]
    
    def test_no_false_positives(self):
        """Non-technique patterns should not be detected."""
        content = "T123 and T12345 and T1234567"
        result = detect_mitre_techniques(content)
        
        # T123 is too short, T12345 and T1234567 are too long
        assert result["technique_count"] == 0
    
    def test_real_attack_tree_content(self):
        """Real attack tree content should have techniques detected."""
        content = """
        # Credential Stuffing Attack
        
        ## Reconnaissance (T1595)
        - Active Scanning
        
        ## Initial Access
        - **Technique**: [T1110.004](https://attack.mitre.org/techniques/T1110/004/) - Credential Stuffing
        - **Tactic**: Credential Access
        
        ## Execution (T1059)
        - Run automated scripts
        """
        result = detect_mitre_techniques(content)
        
        assert "T1595" in result["mitre_techniques_found"]
        assert "T1110.004" in result["mitre_techniques_found"]
        assert "T1059" in result["mitre_techniques_found"]
        # Note: T1110 is also found in the URL path /T1110/004/
        assert result["technique_count"] == 4
    
    def test_returns_dict_format(self):
        """Result should be a dictionary with expected keys."""
        result = detect_mitre_techniques("Test")
        
        assert isinstance(result, dict)
        assert "mitre_techniques_found" in result
        assert "technique_count" in result


# =============================================================================
# Test calculate_automated_metrics()
# =============================================================================

class TestCalculateAutomatedMetrics:
    """Tests for calculate_automated_metrics() convenience function."""
    
    def test_combines_all_metrics(self):
        """Should combine structural, phase, and technique metrics."""
        content = """# Reconnaissance (T1595)
- Scan network
## Initial Access (T1190)
- Exploit vulnerability"""
        
        result = calculate_automated_metrics(content)
        
        assert "structural" in result
        assert "phase_coverage" in result
        assert "technique_detection" in result
    
    def test_structural_metrics_included(self):
        """Structural metrics should be included."""
        content = "# Root\n## Child"
        result = calculate_automated_metrics(content)
        
        assert result["structural"]["node_count"] == 2
        assert result["structural"]["syntax_valid"] is True
    
    def test_phase_coverage_included(self):
        """Phase coverage should be included."""
        content = "# Reconnaissance\n- Scan"
        result = calculate_automated_metrics(content)
        
        assert "reconnaissance" in result["phase_coverage"]["phases_detected"]
    
    def test_technique_detection_included(self):
        """Technique detection should be included."""
        content = "Execute T1059"
        result = calculate_automated_metrics(content)
        
        assert "T1059" in result["technique_detection"]["mitre_techniques_found"]
    
    def test_empty_content_handled(self):
        """Empty content should be handled gracefully."""
        result = calculate_automated_metrics("")
        
        assert result["structural"]["syntax_valid"] is False
        assert result["phase_coverage"]["coverage_score"] == 0.0
        assert result["technique_detection"]["technique_count"] == 0


# =============================================================================
# Test ATTACK_PHASES constant
# =============================================================================

class TestAttackPhasesConstant:
    """Tests for ATTACK_PHASES constant."""
    
    def test_contains_expected_phases(self):
        """ATTACK_PHASES should contain all expected phases."""
        expected = {
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
        
        assert ATTACK_PHASES == expected
    
    def test_is_set(self):
        """ATTACK_PHASES should be a set."""
        assert isinstance(ATTACK_PHASES, set)
    
    def test_has_12_phases(self):
        """ATTACK_PHASES should have 12 phases."""
        assert len(ATTACK_PHASES) == 12


# =============================================================================
# Test PHASE_KEYWORDS constant
# =============================================================================

class TestPhaseKeywordsConstant:
    """Tests for PHASE_KEYWORDS constant."""
    
    def test_has_keywords_for_all_phases(self):
        """PHASE_KEYWORDS should have entries for all phases."""
        for phase in ATTACK_PHASES:
            assert phase in PHASE_KEYWORDS
            assert len(PHASE_KEYWORDS[phase]) > 0
    
    def test_keywords_are_lowercase(self):
        """All keywords should be lowercase."""
        for phase, keywords in PHASE_KEYWORDS.items():
            for keyword in keywords:
                assert keyword == keyword.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
