"""
Unit Tests for Score Definitions

This module contains unit tests for the score definitions in the tracing module,
verifying:
- ScoreType enum values
- ScoreDefinition dataclass behavior and validation
- THREAT_STATEMENT_SCORES list structure (5 dimensions)
- ATTACK_TREE_SCORES list structure (6 dimensions)
- TTP_MAPPING_SCORES categorical definitions
- TTP_SCORE_VALUES mapping correctness
- Helper functions

Requirements tested:
- 4.1: Define score dimensions for threat statement evaluation
- 5.1: Define score dimensions for attack tree evaluation
- 6.1: Define categorical scores for TTP mapping quality
"""

import pytest

from threatforest.tracing.scores import (
    ATTACK_TREE_SCORES,
    THREAT_STATEMENT_SCORES,
    TTP_MAPPING_SCORES,
    TTP_SCORE_VALUES,
    ScoreDefinition,
    ScoreType,
    get_all_score_definitions,
    get_score_definition,
    get_ttp_numeric_value,
)


class TestScoreType:
    """Tests for ScoreType enum."""
    
    def test_numeric_type_value(self):
        """Verify NUMERIC type has correct value."""
        assert ScoreType.NUMERIC.value == "numeric"
    
    def test_categorical_type_value(self):
        """Verify CATEGORICAL type has correct value."""
        assert ScoreType.CATEGORICAL.value == "categorical"
    
    def test_enum_has_two_types(self):
        """Verify ScoreType has exactly two types."""
        assert len(ScoreType) == 2


class TestScoreDefinition:
    """Tests for ScoreDefinition dataclass."""
    
    def test_numeric_score_creation(self):
        """Verify numeric score definition can be created."""
        score = ScoreDefinition(
            name="test_score",
            score_type=ScoreType.NUMERIC,
            description="A test score"
        )
        
        assert score.name == "test_score"
        assert score.score_type == ScoreType.NUMERIC
        assert score.description == "A test score"
        assert score.categories is None
        assert score.min_value == 0.0
        assert score.max_value == 1.0
    
    def test_categorical_score_creation(self):
        """Verify categorical score definition can be created."""
        categories = ["good", "bad", "neutral"]
        score = ScoreDefinition(
            name="test_categorical",
            score_type=ScoreType.CATEGORICAL,
            description="A categorical score",
            categories=categories
        )
        
        assert score.name == "test_categorical"
        assert score.score_type == ScoreType.CATEGORICAL
        assert score.categories == categories
    
    def test_custom_range_numeric_score(self):
        """Verify numeric score with custom range can be created."""
        score = ScoreDefinition(
            name="custom_range",
            score_type=ScoreType.NUMERIC,
            description="Custom range score",
            min_value=-1.0,
            max_value=1.0
        )
        
        assert score.min_value == -1.0
        assert score.max_value == 1.0
    
    def test_categorical_without_categories_raises_error(self):
        """Verify categorical score without categories raises ValueError."""
        with pytest.raises(ValueError, match="categorical but no categories"):
            ScoreDefinition(
                name="invalid",
                score_type=ScoreType.CATEGORICAL,
                description="Invalid categorical"
            )
    
    def test_numeric_with_categories_raises_error(self):
        """Verify numeric score with categories raises ValueError."""
        with pytest.raises(ValueError, match="numeric but categories were provided"):
            ScoreDefinition(
                name="invalid",
                score_type=ScoreType.NUMERIC,
                description="Invalid numeric",
                categories=["a", "b"]
            )
    
    def test_invalid_range_raises_error(self):
        """Verify invalid range raises ValueError."""
        with pytest.raises(ValueError, match="invalid range"):
            ScoreDefinition(
                name="invalid",
                score_type=ScoreType.NUMERIC,
                description="Invalid range",
                min_value=1.0,
                max_value=0.0
            )
    
    def test_equal_range_raises_error(self):
        """Verify equal min/max raises ValueError."""
        with pytest.raises(ValueError, match="invalid range"):
            ScoreDefinition(
                name="invalid",
                score_type=ScoreType.NUMERIC,
                description="Equal range",
                min_value=0.5,
                max_value=0.5
            )
    
    def test_validate_value_accepts_valid_range(self):
        """Verify validate_value accepts values in range."""
        score = ScoreDefinition(
            name="test",
            score_type=ScoreType.NUMERIC,
            description="Test"
        )
        
        assert score.validate_value(0.0) is True
        assert score.validate_value(0.5) is True
        assert score.validate_value(1.0) is True
    
    def test_validate_value_rejects_out_of_range(self):
        """Verify validate_value rejects values outside range."""
        score = ScoreDefinition(
            name="test",
            score_type=ScoreType.NUMERIC,
            description="Test"
        )
        
        with pytest.raises(ValueError, match="outside range"):
            score.validate_value(-0.1)
        
        with pytest.raises(ValueError, match="outside range"):
            score.validate_value(1.1)
    
    def test_validate_category_accepts_valid_category(self):
        """Verify validate_category accepts valid categories."""
        score = ScoreDefinition(
            name="test",
            score_type=ScoreType.CATEGORICAL,
            description="Test",
            categories=["a", "b", "c"]
        )
        
        assert score.validate_category("a") is True
        assert score.validate_category("b") is True
        assert score.validate_category("c") is True
    
    def test_validate_category_rejects_invalid_category(self):
        """Verify validate_category rejects invalid categories."""
        score = ScoreDefinition(
            name="test",
            score_type=ScoreType.CATEGORICAL,
            description="Test",
            categories=["a", "b", "c"]
        )
        
        with pytest.raises(ValueError, match="not in allowed categories"):
            score.validate_category("d")


class TestThreatStatementScores:
    """Tests for THREAT_STATEMENT_SCORES definitions."""
    
    def test_has_five_dimensions(self):
        """Verify THREAT_STATEMENT_SCORES has exactly 5 dimensions."""
        assert len(THREAT_STATEMENT_SCORES) == 5
    
    def test_all_scores_are_categorical(self):
        """Verify all threat statement scores are categorical."""
        for score in THREAT_STATEMENT_SCORES:
            assert score.score_type == ScoreType.CATEGORICAL
    
    def test_contains_overall_quality(self):
        """Verify overall_quality score exists."""
        names = [s.name for s in THREAT_STATEMENT_SCORES]
        assert "overall_quality" in names
    
    def test_contains_relevance_to_context(self):
        """Verify relevance_to_context score exists."""
        names = [s.name for s in THREAT_STATEMENT_SCORES]
        assert "relevance_to_context" in names
    
    def test_contains_completeness(self):
        """Verify completeness score exists."""
        names = [s.name for s in THREAT_STATEMENT_SCORES]
        assert "completeness" in names
    
    def test_contains_technical_accuracy(self):
        """Verify technical_accuracy score exists."""
        names = [s.name for s in THREAT_STATEMENT_SCORES]
        assert "technical_accuracy" in names
    
    def test_contains_hallucination_score(self):
        """Verify hallucination_score exists."""
        names = [s.name for s in THREAT_STATEMENT_SCORES]
        assert "hallucination_score" in names
    
    def test_all_have_descriptions(self):
        """Verify all scores have non-empty descriptions."""
        for score in THREAT_STATEMENT_SCORES:
            assert score.description
            assert len(score.description) > 0
    
    def test_all_have_standard_categories(self):
        """Verify all scores use the standard 5-point categorical scale."""
        from threatforest.tracing.scores import STANDARD_CATEGORIES
        for score in THREAT_STATEMENT_SCORES:
            assert score.categories == STANDARD_CATEGORIES


class TestAttackTreeScores:
    """Tests for ATTACK_TREE_SCORES definitions."""
    
    def test_has_six_dimensions(self):
        """Verify ATTACK_TREE_SCORES has exactly 6 dimensions."""
        assert len(ATTACK_TREE_SCORES) == 6
    
    def test_all_scores_are_categorical(self):
        """Verify all attack tree scores are categorical."""
        for score in ATTACK_TREE_SCORES:
            assert score.score_type == ScoreType.CATEGORICAL
    
    def test_contains_overall_quality(self):
        """Verify overall_quality score exists."""
        names = [s.name for s in ATTACK_TREE_SCORES]
        assert "overall_quality" in names
    
    def test_contains_structural_quality(self):
        """Verify structural_quality score exists."""
        names = [s.name for s in ATTACK_TREE_SCORES]
        assert "structural_quality" in names
    
    def test_contains_technical_realism(self):
        """Verify technical_realism score exists."""
        names = [s.name for s in ATTACK_TREE_SCORES]
        assert "technical_realism" in names
    
    def test_contains_attack_path_logic(self):
        """Verify attack_path_logic score exists."""
        names = [s.name for s in ATTACK_TREE_SCORES]
        assert "attack_path_logic" in names
    
    def test_contains_completeness(self):
        """Verify completeness score exists."""
        names = [s.name for s in ATTACK_TREE_SCORES]
        assert "completeness" in names
    
    def test_contains_actionability(self):
        """Verify actionability score exists."""
        names = [s.name for s in ATTACK_TREE_SCORES]
        assert "actionability" in names
    
    def test_all_have_descriptions(self):
        """Verify all scores have non-empty descriptions."""
        for score in ATTACK_TREE_SCORES:
            assert score.description
            assert len(score.description) > 0


class TestTTPMappingScores:
    """Tests for TTP_MAPPING_SCORES definitions."""
    
    def test_has_one_dimension(self):
        """Verify TTP_MAPPING_SCORES has exactly 1 dimension."""
        assert len(TTP_MAPPING_SCORES) == 1
    
    def test_mapping_quality_is_categorical(self):
        """Verify mapping_quality score is categorical."""
        score = TTP_MAPPING_SCORES[0]
        assert score.name == "mapping_quality"
        assert score.score_type == ScoreType.CATEGORICAL
    
    def test_has_five_categories(self):
        """Verify mapping_quality has 5 categories."""
        score = TTP_MAPPING_SCORES[0]
        assert len(score.categories) == 5
    
    def test_contains_excellent_category(self):
        """Verify excellent category exists."""
        score = TTP_MAPPING_SCORES[0]
        assert "excellent" in score.categories
    
    def test_contains_good_category(self):
        """Verify good category exists."""
        score = TTP_MAPPING_SCORES[0]
        assert "good" in score.categories
    
    def test_contains_acceptable_category(self):
        """Verify acceptable category exists."""
        score = TTP_MAPPING_SCORES[0]
        assert "acceptable" in score.categories
    
    def test_contains_poor_category(self):
        """Verify poor category exists."""
        score = TTP_MAPPING_SCORES[0]
        assert "poor" in score.categories
    
    def test_contains_no_mapping_category(self):
        """Verify no_mapping category exists."""
        score = TTP_MAPPING_SCORES[0]
        assert "no_mapping" in score.categories


class TestTTPScoreValues:
    """Tests for TTP_SCORE_VALUES mapping."""
    
    def test_excellent_maps_to_one(self):
        """Verify excellent maps to 1.0."""
        assert TTP_SCORE_VALUES["excellent"] == 1.0
    
    def test_good_maps_to_075(self):
        """Verify good maps to 0.75."""
        assert TTP_SCORE_VALUES["good"] == 0.75
    
    def test_acceptable_maps_to_05(self):
        """Verify acceptable maps to 0.5."""
        assert TTP_SCORE_VALUES["acceptable"] == 0.5
    
    def test_poor_maps_to_025(self):
        """Verify poor maps to 0.25."""
        assert TTP_SCORE_VALUES["poor"] == 0.25
    
    def test_no_mapping_maps_to_zero(self):
        """Verify no_mapping maps to 0.0."""
        assert TTP_SCORE_VALUES["no_mapping"] == 0.0
    
    def test_has_five_mappings(self):
        """Verify TTP_SCORE_VALUES has exactly 5 mappings."""
        assert len(TTP_SCORE_VALUES) == 5
    
    def test_values_are_in_descending_order(self):
        """Verify values are in descending order of quality."""
        assert TTP_SCORE_VALUES["excellent"] > TTP_SCORE_VALUES["good"]
        assert TTP_SCORE_VALUES["good"] > TTP_SCORE_VALUES["acceptable"]
        assert TTP_SCORE_VALUES["acceptable"] > TTP_SCORE_VALUES["poor"]
        assert TTP_SCORE_VALUES["poor"] > TTP_SCORE_VALUES["no_mapping"]
    
    def test_all_values_in_valid_range(self):
        """Verify all values are in [0.0, 1.0] range."""
        for value in TTP_SCORE_VALUES.values():
            assert 0.0 <= value <= 1.0


class TestGetScoreDefinition:
    """Tests for get_score_definition helper function."""
    
    def test_finds_existing_score(self):
        """Verify function finds existing score by name."""
        score = get_score_definition("overall_quality", THREAT_STATEMENT_SCORES)
        
        assert score is not None
        assert score.name == "overall_quality"
    
    def test_returns_none_for_nonexistent_score(self):
        """Verify function returns None for nonexistent score."""
        score = get_score_definition("nonexistent", THREAT_STATEMENT_SCORES)
        
        assert score is None
    
    def test_finds_score_in_attack_tree_list(self):
        """Verify function works with attack tree scores."""
        score = get_score_definition("structural_quality", ATTACK_TREE_SCORES)
        
        assert score is not None
        assert score.name == "structural_quality"
    
    def test_finds_score_in_ttp_list(self):
        """Verify function works with TTP scores."""
        score = get_score_definition("mapping_quality", TTP_MAPPING_SCORES)
        
        assert score is not None
        assert score.name == "mapping_quality"


class TestGetTTPNumericValue:
    """Tests for get_ttp_numeric_value helper function."""
    
    def test_excellent_returns_one(self):
        """Verify excellent returns 1.0."""
        assert get_ttp_numeric_value("excellent") == 1.0
    
    def test_good_returns_075(self):
        """Verify good returns 0.75."""
        assert get_ttp_numeric_value("good") == 0.75
    
    def test_acceptable_returns_05(self):
        """Verify acceptable returns 0.5."""
        assert get_ttp_numeric_value("acceptable") == 0.5
    
    def test_poor_returns_025(self):
        """Verify poor returns 0.25."""
        assert get_ttp_numeric_value("poor") == 0.25
    
    def test_no_mapping_returns_zero(self):
        """Verify no_mapping returns 0.0."""
        assert get_ttp_numeric_value("no_mapping") == 0.0
    
    def test_invalid_category_raises_error(self):
        """Verify invalid category raises ValueError."""
        with pytest.raises(ValueError, match="Invalid TTP category"):
            get_ttp_numeric_value("invalid")


class TestGetAllScoreDefinitions:
    """Tests for get_all_score_definitions helper function."""
    
    def test_returns_combined_list(self):
        """Verify function returns all score definitions."""
        all_scores = get_all_score_definitions()
        
        # 5 threat + 6 attack tree + 1 TTP = 12 total
        assert len(all_scores) == 12
    
    def test_contains_threat_statement_scores(self):
        """Verify result contains threat statement scores."""
        all_scores = get_all_score_definitions()
        names = [s.name for s in all_scores]
        
        assert "hallucination_score" in names
    
    def test_contains_attack_tree_scores(self):
        """Verify result contains attack tree scores."""
        all_scores = get_all_score_definitions()
        names = [s.name for s in all_scores]
        
        assert "actionability" in names
    
    def test_contains_ttp_scores(self):
        """Verify result contains TTP scores."""
        all_scores = get_all_score_definitions()
        names = [s.name for s in all_scores]
        
        assert "mapping_quality" in names
