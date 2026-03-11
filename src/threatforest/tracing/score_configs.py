"""
Score Configuration Registration for Langfuse

This module provides functionality for registering ThreatForest score definitions
with Langfuse's score_configs API. This enables server-side validation of scores
and ensures consistency across the team.

Score configs in Langfuse:
- Define the schema for scores (numeric, categorical, boolean)
- Enable validation when scores are created
- Provide UI hints for human annotation workflows
- Are immutable once created (can only be archived)

The module supports:
- Registering all ThreatForest score definitions on startup
- Syncing local definitions with existing Langfuse configs
- Retrieving config IDs for score creation with validation
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING
import logging

from threatforest.tracing.config import LangfuseConfig
from threatforest.tracing.scores import (
    ScoreDefinition,
    ScoreType,
    THREAT_STATEMENT_SCORES,
    ATTACK_TREE_SCORES,
    TTP_MAPPING_SCORES,
    MITIGATION_SCORES,
    TTP_SCORE_VALUES,
    get_all_score_definitions,
)

# Import Langfuse at module level for easier mocking in tests
try:
    from langfuse import Langfuse
    from langfuse.api import CreateScoreConfigRequest, ScoreDataType, ConfigCategory
except ImportError:
    Langfuse = None  # type: ignore
    CreateScoreConfigRequest = None  # type: ignore
    ScoreDataType = None  # type: ignore
    ConfigCategory = None  # type: ignore

# UpdateScoreConfigRequest is only available in newer langfuse versions (post-2.61+).
# Import separately so older versions don't break the entire module.
try:
    from langfuse.api import UpdateScoreConfigRequest
except ImportError:
    UpdateScoreConfigRequest = None  # type: ignore

if TYPE_CHECKING:
    from langfuse import Langfuse as LangfuseType

logger = logging.getLogger(__name__)


@dataclass
class RegisteredScoreConfig:
    """
    Represents a score config that has been registered with Langfuse.
    
    Attributes:
        name: The score config name (matches ScoreDefinition.name)
        config_id: The Langfuse-assigned config ID
        data_type: The Langfuse data type (NUMERIC, CATEGORICAL, BOOLEAN)
        is_archived: Whether the config is archived in Langfuse
    """
    name: str
    config_id: str
    data_type: str
    is_archived: bool = False


class ScoreConfigRegistry:
    """
    Registry for managing Langfuse score configurations.
    
    This class handles the registration and retrieval of score configs
    from Langfuse. It maintains a local cache of registered configs
    to avoid repeated API calls.
    
    The registry supports:
    - Registering new score configs from ScoreDefinition objects
    - Retrieving existing configs by name
    - Syncing local definitions with Langfuse on startup
    
    Example:
        >>> config = LangfuseConfig.from_env()
        >>> registry = ScoreConfigRegistry(config)
        >>> registry.register_all_score_definitions()
        >>> config_id = registry.get_config_id("overall_quality")
    """
    
    def __init__(self, langfuse_config: LangfuseConfig):
        """
        Initialize the ScoreConfigRegistry.
        
        Args:
            langfuse_config: Configuration for connecting to Langfuse.
        """
        self._config = langfuse_config
        self._client: Optional["Langfuse"] = None
        self._registered_configs: Dict[str, RegisteredScoreConfig] = {}
        self._initialized = False
        
        if langfuse_config.enabled:
            self._client = self._init_client()
    
    def _init_client(self) -> Optional["LangfuseType"]:
        """Initialize the Langfuse client."""
        if not self._config.enabled:
            return None
        
        try:
            self._config.validate()
            if Langfuse is None:
                raise ImportError("langfuse package not installed")
            return Langfuse(
                public_key=self._config.public_key,
                secret_key=self._config.secret_key,
                host=self._config.host
            )
        except ImportError:
            logger.warning(
                "langfuse package not installed, score config registration disabled"
            )
            return None
        except ValueError as e:
            logger.warning(f"Invalid Langfuse config: {e}")
            return None
    
    def _convert_score_type_to_langfuse(self, score_def: ScoreDefinition) -> Any:
        """
        Convert ScoreType to Langfuse ScoreDataType enum.
        
        Args:
            score_def: The score definition to convert.
        
        Returns:
            Langfuse ScoreDataType enum value.
        """
        if ScoreDataType is None:
            # Fallback to string if langfuse not installed
            if score_def.score_type == ScoreType.NUMERIC:
                return "NUMERIC"
            elif score_def.score_type == ScoreType.CATEGORICAL:
                return "CATEGORICAL"
            else:
                return "NUMERIC"
        
        if score_def.score_type == ScoreType.NUMERIC:
            return ScoreDataType.NUMERIC
        elif score_def.score_type == ScoreType.CATEGORICAL:
            return ScoreDataType.CATEGORICAL
        else:
            return ScoreDataType.NUMERIC  # Default fallback
    
    def _build_categories_for_langfuse(
        self,
        score_def: ScoreDefinition
    ) -> Optional[List[Any]]:
        """
        Build Langfuse ConfigCategory objects from ScoreDefinition.
        
        For categorical scores, Langfuse expects a list of ConfigCategory
        objects with 'label' and 'value' properties. For TTP scores, we use the
        TTP_SCORE_VALUES mapping to assign numeric values.
        
        Args:
            score_def: The score definition with categories.
        
        Returns:
            List of ConfigCategory objects for Langfuse, or None for numeric scores.
        """
        if score_def.score_type != ScoreType.CATEGORICAL:
            return None
        
        if not score_def.categories:
            return None
        
        categories = []
        for category in score_def.categories:
            # Use TTP_SCORE_VALUES if available, otherwise use index-based values
            if category in TTP_SCORE_VALUES:
                value = TTP_SCORE_VALUES[category]
            else:
                # Assign values based on position (1.0 for first, decreasing)
                idx = score_def.categories.index(category)
                value = 1.0 - (idx / max(len(score_def.categories) - 1, 1))
            
            if ConfigCategory is not None:
                categories.append(ConfigCategory(label=category, value=value))
            else:
                # Fallback to dict if langfuse not installed
                categories.append({"label": category, "value": value})
        
        return categories
    
    def _archive_config(self, config_id: str, config_name: str) -> bool:
        """
        Archive a score config in Langfuse.
        
        Args:
            config_id: The Langfuse config ID to archive.
            config_name: The config name (for logging).
        
        Returns:
            True if archived successfully, False otherwise.
        """
        if not self._client:
            return False
        
        try:
            if UpdateScoreConfigRequest is not None:
                request = UpdateScoreConfigRequest(is_archived=True)
                self._client.api.score_configs.update(
                    config_id=config_id, request=request
                )
            else:
                # Fallback for older langfuse SDK versions without UpdateScoreConfigRequest.
                # Use the HTTP client directly.
                self._client.api.score_configs._client_wrapper.httpx_client.request(
                    "PATCH",
                    f"{self._client.api.score_configs._client_wrapper.get_base_url()}/api/public/score-configs/{config_id}",
                    json={"isArchived": True},
                    headers=self._client.api.score_configs._client_wrapper.get_headers(),
                )
            logger.info(f"Archived score config: {config_name} (id={config_id})")
            return True
        except Exception as e:
            logger.warning(
                f"Failed to archive score config '{config_name}': {e}. "
                f"Please archive it manually in the Langfuse UI, then re-run --register-scores."
            )
            return False

    def register_score_definition(
        self,
        score_def: ScoreDefinition,
        prefix: str = ""
    ) -> Optional[RegisteredScoreConfig]:
        """
        Register a single score definition with Langfuse.
        
        If a config with the same name already exists and matches the expected
        data type, it will be reused. If the data type has changed (e.g.,
        NUMERIC → CATEGORICAL), the old config is archived and a new one
        is created.
        
        Args:
            score_def: The score definition to register.
            prefix: Optional prefix to add to the score name (e.g., "threat_").
        
        Returns:
            RegisteredScoreConfig if successful, None if registration failed.
        """
        if not self._client:
            logger.debug("Langfuse client not available, skipping registration")
            return None
        
        config_name = f"{prefix}{score_def.name}" if prefix else score_def.name
        
        # Check if already registered locally
        if config_name in self._registered_configs:
            return self._registered_configs[config_name]
        
        # Determine expected data type string
        expected_type = score_def.score_type.value.upper()  # "NUMERIC" or "CATEGORICAL"
        
        # Check if exists in Langfuse (skip archived)
        existing = self._get_existing_config(config_name)
        if existing:
            existing_type = existing.data_type.upper() if isinstance(
                existing.data_type, str
            ) else str(existing.data_type).upper()
            
            if expected_type in existing_type:
                # Same type — reuse
                self._registered_configs[config_name] = existing
                logger.debug(f"Found existing score config: {config_name}")
                return existing
            else:
                # Type mismatch — archive old config and create new one
                logger.info(
                    f"Score config '{config_name}' type mismatch: "
                    f"existing={existing_type}, expected={expected_type}. "
                    f"Archiving old config and creating new one."
                )
                self._archive_config(existing.config_id, config_name)
        
        # Create new config in Langfuse
        try:
            data_type = self._convert_score_type_to_langfuse(score_def)
            categories = self._build_categories_for_langfuse(score_def)
            
            if CreateScoreConfigRequest is None:
                raise ImportError("langfuse package not installed")
            
            # Build CreateScoreConfigRequest with snake_case field names
            request_kwargs: Dict[str, Any] = {
                "name": config_name,
                "data_type": data_type,
            }
            
            if score_def.description:
                request_kwargs["description"] = score_def.description
            
            if score_def.score_type == ScoreType.NUMERIC:
                request_kwargs["min_value"] = score_def.min_value
                request_kwargs["max_value"] = score_def.max_value
            
            if categories:
                request_kwargs["categories"] = categories
            
            request = CreateScoreConfigRequest(**request_kwargs)
            response = self._client.api.score_configs.create(request=request)
            
            # Store data_type as string for RegisteredScoreConfig
            data_type_str = (
                data_type.value if hasattr(data_type, 'value') else str(data_type)
            )
            
            registered = RegisteredScoreConfig(
                name=config_name,
                config_id=response.id,
                data_type=data_type_str,
                is_archived=False
            )
            
            self._registered_configs[config_name] = registered
            logger.info(f"Registered score config: {config_name} (id={response.id})")
            return registered
            
        except Exception as e:
            logger.warning(f"Failed to register score config '{config_name}': {e}")
            return None
    
    def _get_existing_config(
        self, name: str, include_archived: bool = False
    ) -> Optional[RegisteredScoreConfig]:
        """
        Check if a score config already exists in Langfuse.
        
        Args:
            name: The config name to search for.
            include_archived: If False (default), skip archived configs.
        
        Returns:
            RegisteredScoreConfig if found, None otherwise.
        """
        if not self._client:
            return None
        
        try:
            # Fetch all score configs and find by name
            response = self._client.api.score_configs.get()
            
            for config in response.data:
                if config.name == name:
                    is_archived = getattr(config, 'is_archived', False)
                    if is_archived and not include_archived:
                        continue
                    
                    data_type_str = (
                        config.data_type.value
                        if hasattr(config.data_type, 'value')
                        else str(config.data_type)
                    )
                    return RegisteredScoreConfig(
                        name=config.name,
                        config_id=config.id,
                        data_type=data_type_str,
                        is_archived=is_archived
                    )
            
            return None
            
        except Exception as e:
            logger.debug(f"Error fetching score configs: {e}")
            return None
    
    def register_all_score_definitions(
        self,
        include_prefix: bool = True
    ) -> Dict[str, RegisteredScoreConfig]:
        """
        Register all ThreatForest score definitions with Langfuse.
        
        This method registers all score definitions from:
        - THREAT_STATEMENT_SCORES (prefixed with "threat_" if include_prefix=True)
        - ATTACK_TREE_SCORES (prefixed with "attack_tree_" if include_prefix=True)
        - TTP_MAPPING_SCORES (prefixed with "ttp_" if include_prefix=True)
        
        Args:
            include_prefix: Whether to prefix score names with their category.
        
        Returns:
            Dictionary mapping score names to their registered configs.
        """
        if not self._client:
            logger.info("Langfuse not enabled, skipping score config registration")
            return {}
        
        registered: Dict[str, RegisteredScoreConfig] = {}
        
        # Register threat statement scores
        prefix = "threat_" if include_prefix else ""
        for score_def in THREAT_STATEMENT_SCORES:
            config = self.register_score_definition(score_def, prefix)
            if config:
                registered[config.name] = config
        
        # Register attack tree scores
        prefix = "attack_tree_" if include_prefix else ""
        for score_def in ATTACK_TREE_SCORES:
            config = self.register_score_definition(score_def, prefix)
            if config:
                registered[config.name] = config
        
        # Register TTP mapping scores
        prefix = "ttp_" if include_prefix else ""
        for score_def in TTP_MAPPING_SCORES:
            config = self.register_score_definition(score_def, prefix)
            if config:
                registered[config.name] = config
        
        # Register mitigation scores
        prefix = "mitigation_" if include_prefix else ""
        for score_def in MITIGATION_SCORES:
            config = self.register_score_definition(score_def, prefix)
            if config:
                registered[config.name] = config
        
        logger.info(f"Registered {len(registered)} score configs with Langfuse")
        return registered
    
    def get_config_id(self, name: str) -> Optional[str]:
        """
        Get the Langfuse config ID for a score name.
        
        Args:
            name: The score config name.
        
        Returns:
            The Langfuse config ID, or None if not registered.
        """
        config = self._registered_configs.get(name)
        return config.config_id if config else None
    
    def get_registered_configs(self) -> Dict[str, RegisteredScoreConfig]:
        """
        Get all registered score configs.
        
        Returns:
            Dictionary mapping score names to their registered configs.
        """
        return self._registered_configs.copy()
    
    def is_registered(self, name: str) -> bool:
        """
        Check if a score config is registered.
        
        Args:
            name: The score config name.
        
        Returns:
            True if registered, False otherwise.
        """
        return name in self._registered_configs
    
    def sync_with_langfuse(self) -> None:
        """
        Sync local registry with existing Langfuse score configs.
        
        This method fetches all score configs from Langfuse and updates
        the local registry. Useful for initializing the registry with
        configs that were created outside this application.
        """
        if not self._client:
            return
        
        try:
            response = self._client.api.score_configs.get()
            
            for config in response.data:
                if config.name not in self._registered_configs:
                    self._registered_configs[config.name] = RegisteredScoreConfig(
                        name=config.name,
                        config_id=config.id,
                        data_type=config.data_type,
                        is_archived=getattr(config, 'is_archived', False)
                    )
            
            logger.info(
                f"Synced {len(self._registered_configs)} score configs from Langfuse"
            )
            
        except Exception as e:
            logger.warning(f"Failed to sync score configs: {e}")


# Module-level singleton instance
_registry_instance: Optional[ScoreConfigRegistry] = None


def get_score_config_registry(
    config: Optional[LangfuseConfig] = None
) -> ScoreConfigRegistry:
    """
    Get the singleton ScoreConfigRegistry instance.
    
    Args:
        config: Optional Langfuse configuration. If not provided,
               configuration will be loaded from environment variables.
    
    Returns:
        ScoreConfigRegistry: The singleton registry instance.
    """
    global _registry_instance
    
    if _registry_instance is None:
        config = config or LangfuseConfig.from_env()
        _registry_instance = ScoreConfigRegistry(config)
    
    return _registry_instance


def reset_score_config_registry() -> None:
    """
    Reset the singleton registry instance.
    
    This is primarily for testing purposes.
    """
    global _registry_instance
    _registry_instance = None
