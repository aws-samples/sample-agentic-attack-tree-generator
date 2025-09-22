"""
Information extraction using LLM for application context analysis.
"""

import json
from typing import Dict, Any, List, Optional

from .models import ApplicationInfo
from .llm_client import LLMClient
from .context_parser import ParsedContent
from .exceptions import LLMError, FileProcessingError
from .utils import get_logger


class InfoExtractor:
    """Extracts structured information from application context using LLM."""
    
    def __init__(self, llm_client: LLMClient):
        self.llm_client = llm_client
        self.logger = get_logger(__name__)
    
    def extract_application_info(self, parsed_files: List[ParsedContent]) -> ApplicationInfo:
        """
        Extract application information from parsed context files.
        
        Args:
            parsed_files: List of parsed content objects
            
        Returns:
            ApplicationInfo object with extracted data
        """
        self.logger.info("Extracting application information using LLM")
        
        # Combine context from all files
        context = self._prepare_context(parsed_files)
        
        # Create extraction prompt
        prompt = self.llm_client.create_extraction_prompt(context, "app_info")
        
        try:
            # Get LLM response
            response = self.llm_client.generate(prompt)
            
            # Validate and parse response
            if not self.llm_client.validate_response(response, "json"):
                raise LLMError("LLM response is not valid JSON")
            
            # Parse JSON response
            extracted_data = json.loads(response.content)
            
            # Create ApplicationInfo object
            app_info = self._create_application_info(extracted_data)
            
            self.logger.info(f"Successfully extracted application info: {app_info.name}")
            return app_info
            
        except json.JSONDecodeError as e:
            raise LLMError(f"Failed to parse LLM response as JSON: {e}")
        except Exception as e:
            raise LLMError(f"Error during information extraction: {e}")
    
    def _prepare_context(self, parsed_files: List[ParsedContent]) -> str:
        """Prepare context string from parsed files."""
        context_parts = []
        
        # Prioritize certain file types
        file_priority = {
            'readme': 1,
            'threat_statements': 2,
            'architecture_diagram': 3,
            'data_flow_diagram': 4
        }
        
        # Sort files by priority
        sorted_files = sorted(
            parsed_files,
            key=lambda f: file_priority.get(f.file_type.value, 5)
        )
        
        for parsed in sorted_files:
            header = f"\n=== {parsed.file_type.value.upper()}: {parsed.file_path.name} ===\n"
            context_parts.append(header)
            
            # Limit content length to avoid token limits
            content = parsed.content
            if len(content) > 8000:  # Rough token limit
                content = content[:8000] + "\n... [content truncated]"
            
            context_parts.append(content)
            context_parts.append("\n")
        
        return "\n".join(context_parts)
    
    def _create_application_info(self, extracted_data: Dict[str, Any]) -> ApplicationInfo:
        """Create ApplicationInfo object from extracted data."""
        return ApplicationInfo(
            name=extracted_data.get('name', 'Unknown Application'),
            description=extracted_data.get('description', ''),
            technologies=extracted_data.get('technologies', []),
            programming_languages=extracted_data.get('programming_languages', []),
            sector=extracted_data.get('sector', ''),
            security_objectives=extracted_data.get('security_objectives', []),
            additional_context=extracted_data.get('additional_context', {})
        )
    
    def enhance_with_metadata(self, app_info: ApplicationInfo, parsed_files: List[ParsedContent]) -> ApplicationInfo:
        """
        Enhance application info with metadata from parsed files.
        
        Args:
            app_info: Base application info
            parsed_files: Parsed files with metadata
            
        Returns:
            Enhanced ApplicationInfo object
        """
        # Collect technologies mentioned in metadata
        all_technologies = set(app_info.technologies)
        
        for parsed in parsed_files:
            if 'mentioned_technologies' in parsed.metadata:
                all_technologies.update(parsed.metadata['mentioned_technologies'])
        
        # Update application info
        app_info.technologies = list(all_technologies)
        
        # Add file metadata to additional context
        file_summary = {}
        for parsed in parsed_files:
            file_type = parsed.file_type.value
            file_summary[file_type] = {
                'file_name': parsed.file_path.name,
                'size': parsed.metadata.get('size', 0),
                'format': parsed.metadata.get('format', 'unknown')
            }
        
        app_info.additional_context['source_files'] = file_summary
        
        return app_info