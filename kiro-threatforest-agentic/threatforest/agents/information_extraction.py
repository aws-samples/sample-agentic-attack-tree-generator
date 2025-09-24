"""
Information Extraction Agent for ThreatForest.

This agent processes context files to extract key security information including
technologies, programming languages, security objectives, and other metadata
needed for threat modeling. It uses AI to analyze content and provides user
validation interfaces.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

from ..models import ContextInformation, ValidationStatus
from ..utils.bedrock_client import BedrockClient, BedrockClientError
from .context_detection import DetectedFile, FileType, FileFormat


logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    """Result of information extraction process."""
    
    context_info: ContextInformation
    extraction_confidence: float
    source_files: List[str]
    processing_errors: List[str]
    ai_reasoning: str
    
    def is_high_confidence(self, threshold: float = 0.7) -> bool:
        """Check if extraction confidence meets threshold."""
        return self.extraction_confidence >= threshold


class InformationExtractionAgent:
    """
    Agent responsible for extracting security information from context files.
    
    Uses AI to analyze README files, architecture diagrams, and other context
    documents to extract technologies, security objectives, and metadata.
    """
    
    def __init__(self, bedrock_client: BedrockClient):
        """
        Initialize the Information Extraction Agent.
        
        Args:
            bedrock_client: Bedrock client for AI processing
        """
        self.bedrock_client = bedrock_client
        
        # System prompt for information extraction
        self.system_prompt = """You are a security analyst assistant that extracts key information from application documentation for threat modeling purposes.

Your task is to analyze the provided context files and extract:
1. Technologies and frameworks used
2. Programming languages
3. Business sector/domain
4. Security objectives (Confidentiality, Integrity, Availability)
5. Architecture type
6. Compliance frameworks mentioned

Respond with a JSON object containing:
{
    "technologies": ["list of technologies/frameworks"],
    "programming_languages": ["list of programming languages"],
    "sector": "business sector or null",
    "security_objectives": ["list from: confidentiality, integrity, availability"],
    "architecture_type": "architecture type or null",
    "compliance_frameworks": ["list of compliance frameworks"],
    "confidence_score": 0.0-1.0,
    "reasoning": "explanation of your analysis"
}

Be conservative in your assessments. Only include items you are confident about.
For security_objectives, only include those explicitly mentioned or clearly implied.
Use lowercase for security objectives and compliance frameworks."""
    
    def extract_information(self, detected_files: List[DetectedFile]) -> ExtractionResult:
        """
        Extract security information from detected context files.
        
        Args:
            detected_files: List of detected and validated context files
            
        Returns:
            ExtractionResult with extracted information
        """
        logger.info(f"Starting information extraction from {len(detected_files)} files")
        
        processing_errors = []
        source_files = []
        
        # Filter to valid, readable files
        valid_files = [f for f in detected_files if f.is_valid() and f.is_readable()]
        
        if not valid_files:
            logger.warning("No valid files available for information extraction")
            return self._create_empty_result(["No valid files available for extraction"])
        
        # Prepare content for AI analysis
        try:
            content_summary = self._prepare_content_for_analysis(valid_files)
            source_files = [str(f.path) for f in valid_files]
            
            logger.debug(f"Prepared content summary with {len(content_summary)} characters")
            
        except Exception as e:
            error_msg = f"Error preparing content for analysis: {e}"
            logger.error(error_msg)
            processing_errors.append(error_msg)
            return self._create_empty_result(processing_errors)
        
        # Extract information using AI
        try:
            extraction_result = self._extract_with_ai(content_summary)
            
            # Create ContextInformation object
            context_info = ContextInformation(
                technologies=extraction_result.get("technologies", []),
                programming_languages=extraction_result.get("programming_languages", []),
                sector=extraction_result.get("sector"),
                security_objectives=extraction_result.get("security_objectives", []),
                architecture_type=extraction_result.get("architecture_type"),
                compliance_frameworks=extraction_result.get("compliance_frameworks", []),
                extracted_from=source_files,
                validation_status=ValidationStatus.PENDING,
                confidence_score=extraction_result.get("confidence_score", 0.0)
            )
            
            logger.info("Information extraction completed successfully")
            
            return ExtractionResult(
                context_info=context_info,
                extraction_confidence=extraction_result.get("confidence_score", 0.0),
                source_files=source_files,
                processing_errors=processing_errors,
                ai_reasoning=extraction_result.get("reasoning", "")
            )
            
        except Exception as e:
            error_msg = f"Error during AI extraction: {e}"
            logger.error(error_msg)
            processing_errors.append(error_msg)
            return self._create_empty_result(processing_errors)
    
    def _prepare_content_for_analysis(self, files: List[DetectedFile]) -> str:
        """
        Prepare file contents for AI analysis.
        
        Args:
            files: List of detected files to analyze
            
        Returns:
            Formatted content string for AI analysis
        """
        content_parts = []
        
        # Prioritize file types for analysis
        file_priority = {
            FileType.README: 1,
            FileType.THREAT_STATEMENT: 2,
            FileType.ARCHITECTURE_DIAGRAM: 3,
            FileType.DATA_FLOW_DIAGRAM: 4,
            FileType.DOCUMENTATION: 5,
            FileType.CONFIGURATION: 6
        }
        
        # Sort files by priority and confidence
        sorted_files = sorted(
            files,
            key=lambda f: (file_priority.get(f.file_type, 10), -f.confidence_score)
        )
        
        for file_info in sorted_files:
            try:
                file_content = self._extract_file_content(file_info)
                if file_content:
                    content_parts.append(f"=== {file_info.file_type.value.upper()}: {file_info.path.name} ===")
                    content_parts.append(file_content)
                    content_parts.append("")  # Empty line separator
                    
            except Exception as e:
                logger.warning(f"Error reading file {file_info.path}: {e}")
                continue
        
        # Combine all content with size limit
        full_content = "\n".join(content_parts)
        
        # Truncate if too long (keep within token limits)
        max_chars = 50000  # Roughly 12-15k tokens
        if len(full_content) > max_chars:
            logger.info(f"Content truncated from {len(full_content)} to {max_chars} characters")
            full_content = full_content[:max_chars] + "\n\n[CONTENT TRUNCATED]"
        
        return full_content
    
    def _extract_file_content(self, file_info: DetectedFile) -> str:
        """
        Extract readable content from a file.
        
        Args:
            file_info: Information about the file to read
            
        Returns:
            Extracted text content
        """
        if file_info.file_format in [FileFormat.PNG, FileFormat.PDF]:
            # For binary files, return metadata only
            return f"[Binary file: {file_info.file_format.value}, {file_info.size_bytes} bytes]"
        
        try:
            # Read text content
            with open(file_info.path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # For very large files, take a sample
            if len(content) > 10000:
                # Take first 8000 chars and last 2000 chars
                content = content[:8000] + "\n\n[... MIDDLE CONTENT TRUNCATED ...]\n\n" + content[-2000:]
            
            return content
            
        except Exception as e:
            logger.warning(f"Error reading file {file_info.path}: {e}")
            return f"[Error reading file: {e}]"
    
    def _extract_with_ai(self, content: str) -> Dict[str, Any]:
        """
        Use AI to extract information from content.
        
        Args:
            content: Prepared content for analysis
            
        Returns:
            Dictionary with extracted information
            
        Raises:
            BedrockClientError: If AI extraction fails
        """
        prompt = f"""Analyze the following application documentation and extract key security-relevant information:

{content}

Extract the information as specified in the system prompt. Focus on:
- Technologies, frameworks, and services mentioned
- Programming languages used
- Business domain/sector if mentioned
- Security requirements or objectives
- Architecture patterns
- Compliance requirements

Provide your analysis as a valid JSON object."""
        
        try:
            response = self.bedrock_client.invoke_model(
                prompt=prompt,
                system_prompt=self.system_prompt,
                max_tokens=2000,
                temperature=0.1
            )
            
            # Parse JSON response
            try:
                result = json.loads(response.content)
                
                # Validate required fields
                if not isinstance(result, dict):
                    raise ValueError("Response is not a JSON object")
                
                # Ensure required fields exist with defaults
                result.setdefault("technologies", [])
                result.setdefault("programming_languages", [])
                result.setdefault("sector", None)
                result.setdefault("security_objectives", [])
                result.setdefault("architecture_type", None)
                result.setdefault("compliance_frameworks", [])
                result.setdefault("confidence_score", 0.5)
                result.setdefault("reasoning", "No reasoning provided")
                
                # Validate and clean data
                result = self._validate_and_clean_extraction(result)
                
                return result
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI response as JSON: {e}")
                logger.debug(f"AI response content: {response.content}")
                raise BedrockClientError(f"Invalid JSON response from AI: {e}")
                
        except BedrockClientError:
            raise
        except Exception as e:
            raise BedrockClientError(f"Unexpected error during AI extraction: {e}")
    
    def _validate_and_clean_extraction(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and clean extracted information.
        
        Args:
            result: Raw extraction result
            
        Returns:
            Cleaned and validated result
        """
        # Clean and validate lists
        if isinstance(result.get("technologies"), list):
            result["technologies"] = [str(t).strip() for t in result["technologies"] if t]
        else:
            result["technologies"] = []
        
        if isinstance(result.get("programming_languages"), list):
            result["programming_languages"] = [str(l).strip() for l in result["programming_languages"] if l]
        else:
            result["programming_languages"] = []
        
        # Validate security objectives
        valid_objectives = {"confidentiality", "integrity", "availability"}
        if isinstance(result.get("security_objectives"), list):
            cleaned_objectives = []
            for obj in result["security_objectives"]:
                obj_lower = str(obj).lower().strip()
                if obj_lower in valid_objectives:
                    cleaned_objectives.append(obj_lower)
            result["security_objectives"] = cleaned_objectives
        else:
            result["security_objectives"] = []
        
        # Clean compliance frameworks
        if isinstance(result.get("compliance_frameworks"), list):
            result["compliance_frameworks"] = [str(f).strip().lower() for f in result["compliance_frameworks"] if f]
        else:
            result["compliance_frameworks"] = []
        
        # Validate confidence score
        try:
            confidence = float(result.get("confidence_score", 0.5))
            result["confidence_score"] = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            result["confidence_score"] = 0.5
        
        # Clean string fields
        for field in ["sector", "architecture_type", "reasoning"]:
            if result.get(field):
                result[field] = str(result[field]).strip()
            else:
                result[field] = None if field != "reasoning" else "No reasoning provided"
        
        return result
    
    def _create_empty_result(self, errors: List[str]) -> ExtractionResult:
        """Create an empty extraction result with errors."""
        return ExtractionResult(
            context_info=ContextInformation(
                validation_status=ValidationStatus.REJECTED,
                confidence_score=0.0
            ),
            extraction_confidence=0.0,
            source_files=[],
            processing_errors=errors,
            ai_reasoning="Extraction failed due to errors"
        )
    
    def validate_with_user(self, extraction_result: ExtractionResult) -> ContextInformation:
        """
        Present extracted information to user for validation.
        
        This is a placeholder for user interaction. In a real implementation,
        this would present the information via CLI or web interface.
        
        Args:
            extraction_result: Result of information extraction
            
        Returns:
            Validated ContextInformation
        """
        logger.info("User validation required for extracted information")
        
        # For now, auto-approve high-confidence extractions
        if extraction_result.is_high_confidence():
            logger.info("Auto-approving high-confidence extraction")
            extraction_result.context_info.validation_status = ValidationStatus.APPROVED
        else:
            logger.warning("Low-confidence extraction requires manual validation")
            extraction_result.context_info.validation_status = ValidationStatus.PENDING
        
        return extraction_result.context_info
    
    def save_extracted_information(
        self,
        context_info: ContextInformation,
        output_path: str,
        include_metadata: bool = True
    ) -> Path:
        """
        Save validated context information to a markdown file.
        
        Args:
            context_info: Validated context information
            output_path: Directory to save the file
            include_metadata: Whether to include extraction metadata
            
        Returns:
            Path to the saved file
        """
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / "extracted_context_info.md"
        
        # Generate markdown content
        content_lines = [
            "# Extracted Context Information",
            "",
            f"**Validation Status:** {context_info.validation_status.value}",
            f"**Confidence Score:** {context_info.confidence_score:.2f}",
            f"**Extraction Date:** {context_info.timestamp.isoformat()}",
            ""
        ]
        
        # Technologies
        if context_info.technologies:
            content_lines.extend([
                "## Technologies and Frameworks",
                "",
                *[f"- {tech}" for tech in context_info.technologies],
                ""
            ])
        
        # Programming Languages
        if context_info.programming_languages:
            content_lines.extend([
                "## Programming Languages",
                "",
                *[f"- {lang}" for lang in context_info.programming_languages],
                ""
            ])
        
        # Business Sector
        if context_info.sector:
            content_lines.extend([
                "## Business Sector",
                "",
                context_info.sector,
                ""
            ])
        
        # Security Objectives
        if context_info.security_objectives:
            content_lines.extend([
                "## Security Objectives",
                "",
                *[f"- {obj.title()}" for obj in context_info.security_objectives],
                ""
            ])
        
        # Architecture Type
        if context_info.architecture_type:
            content_lines.extend([
                "## Architecture Type",
                "",
                context_info.architecture_type,
                ""
            ])
        
        # Compliance Frameworks
        if context_info.compliance_frameworks:
            content_lines.extend([
                "## Compliance Frameworks",
                "",
                *[f"- {framework.upper()}" for framework in context_info.compliance_frameworks],
                ""
            ])
        
        # Source Files
        if include_metadata and context_info.extracted_from:
            content_lines.extend([
                "## Source Files",
                "",
                *[f"- {file}" for file in context_info.extracted_from],
                ""
            ])
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(content_lines))
            
            logger.info(f"Saved extracted context information to: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error saving context information: {e}")
            raise
    
    def update_extraction(
        self,
        context_info: ContextInformation,
        updates: Dict[str, Any]
    ) -> ContextInformation:
        """
        Update extracted information based on user feedback.
        
        Args:
            context_info: Current context information
            updates: Dictionary of updates to apply
            
        Returns:
            Updated ContextInformation
        """
        logger.info("Updating extracted information based on user feedback")
        
        # Create updated data
        updated_data = context_info.model_dump()
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(context_info, key):
                updated_data[key] = value
        
        # Mark as modified
        updated_data['validation_status'] = ValidationStatus.MODIFIED
        
        # Create new instance
        return ContextInformation(**updated_data)