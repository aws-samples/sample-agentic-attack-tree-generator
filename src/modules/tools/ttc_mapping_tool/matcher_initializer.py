"""Matcher initialization for local and Neptune modes"""
from typing import Optional
from pathlib import Path
from botocore.exceptions import ClientError


class MatcherInitializer:
    """Initializes TTCMatcher for local or Neptune mode"""
    
    def __init__(self, logger, threshold: float):
        self.logger = logger
        self.threshold = threshold
    
    def initialize_matcher(self, aws_profile: Optional[str] = None):
        """Initialize TTCMatcher based on config"""
        try:
            from src.config import config
            from ...ttc_mappings import TTCMatcher
            
            mode = config.embeddings_mode
            
            # Configuration details are now shown in the main CLI display
            # with modern formatting and icons - no need to print here
            
            if mode == 'local':
                return self._initialize_local_matcher(config)
            elif mode == 'neptune':
                return self._initialize_neptune_matcher(config, aws_profile)
            else:
                raise ValueError(f"Invalid embeddings mode '{mode}'. Must be 'local' or 'neptune'")
                
        except Exception as e:
            print(f"\n❌ ERROR: {e}\n")
            self.logger.error(f"Failed to initialize matcher: {e}")
            raise
    
    def _initialize_local_matcher(self, config):
        """Initialize local matcher"""
        from ...ttc_mappings import TTCMatcher
        
        embeddings_path = str(config.embeddings_file_path)
        
        matcher = TTCMatcher(
            mode='local',
            embeddings_path=embeddings_path,
            model_name=config.embeddings_model,
            min_similarity=self.threshold
        )
        self.logger.info(f"Local matcher initialized with {embeddings_path}")
        return matcher
    
    def _initialize_neptune_matcher(self, config, aws_profile):
        """Initialize Neptune matcher"""
        import boto3
        from neptune_graph_manager import NeptuneGraphManager
        from ast import literal_eval
        import os
        from ...ttc_mappings import TTCMatcher
        
        graph_id = config.neptune_graph_id
        region = config.neptune_region
        
        if not graph_id:
            raise ValueError("Neptune mode requires graph_id in config.yaml")
        
        # Create Neptune session
        session_params = literal_eval(os.getenv("SESSION_PARAMS", "{}"))
        if aws_profile:
            session = boto3.Session(profile_name=aws_profile, region_name="us-east-1")
        elif session_params:
            session = boto3.Session(**session_params)
        else:
            session = boto3.Session()
        
        # Validate account ID if required
        self._validate_account_id(config, session, region)
        
        neptune_manager = NeptuneGraphManager(
            session=session,
            graph_id=graph_id,
            embedding_model=config.embeddings_model
        )
        self.logger.info(f"Neptune manager initialized for graph {graph_id}")
        
        matcher = TTCMatcher(
            mode='neptune',
            neptune_manager=neptune_manager,
            min_similarity=self.threshold
        )
        self.logger.info(f"Neptune matcher initialized successfully")
        return matcher
    
    def _validate_account_id(self, config, session, region):
        """Validate AWS account ID matches requirements"""
        required_account_id = config.neptune_account_id
        if not required_account_id:
            return
        
        sts_client = session.client('sts', region_name=region)
        
        try:
            identity = sts_client.get_caller_identity()
            current_account_id = identity['Account']
            
            if current_account_id != required_account_id:
                raise ValueError(
                    f"Account ID mismatch! Expected: {required_account_id}, "
                    f"Current: {current_account_id}"
                )
            
            self.logger.info(f"Account ID validated: {current_account_id}")
        except ClientError as e:
            raise ValueError(f"Failed to validate account ID: {e}")
