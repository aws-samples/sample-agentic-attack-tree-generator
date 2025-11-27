"""Matcher initialization"""
from typing import Optional
from pathlib import Path


class MatcherInitializer:
    """Initializes TTCMatcher with local graph"""
    
    def __init__(self, logger, threshold: float):
        self.logger = logger
        self.threshold = threshold
    
    def initialize_matcher(self, aws_profile: Optional[str] = None):
        """Initialize TTCMatcher with local graph (aws_profile kept for compatibility)"""
        try:
            from .matcher import TTCMatcher
            
            # Simple initialization - graph will be lazy-loaded on first use
            matcher = TTCMatcher(min_similarity=self.threshold)
            self.logger.info(f"TTCMatcher initialized (threshold={self.threshold})")
            
            return matcher
                
        except Exception as e:
            print(f"\n❌ ERROR: {e}\n")
            self.logger.error(f"Failed to initialize matcher: {e}")
            raise
