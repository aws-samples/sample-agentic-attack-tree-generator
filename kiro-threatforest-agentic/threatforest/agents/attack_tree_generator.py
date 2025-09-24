"""
Attack Tree Generator Agent for ThreatForest.

This agent creates Mermaid-formatted attack trees from threat statements,
focusing on high-severity threats and generating logical attack paths with
proper color coding and styling.
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from ..models import ThreatStatement, AttackTree, AttackStep, ContextInformation, AttackStepType, SeverityLevel
from ..utils.bedrock_client import BedrockClient, BedrockClientError


logger = logging.getLogger(__name__)


@dataclass
class AttackPath:
    """Represents a logical attack path in the attack tree."""
    
    steps: List[AttackStep]
    path_id: str
    description: str
    likelihood: str  # low, medium, high
    impact: str  # low, medium, high
    
    def get_step_ids(self) -> List[str]:
        """Get list of step IDs in this path."""
        return [step.id for step in self.steps]


@dataclass
class GenerationResult:
    """Result of attack tree generation."""
    
    attack_tree: Optional[AttackTree]
    generation_errors: List[str]
    generation_warnings: List[str]
    skipped_reason: Optional[str]
    processing_time_seconds: float
    
    def is_successful(self) -> bool:
        """Check if generation was successful."""
        return self.attack_tree is not None and len(self.generation_errors) == 0


class AttackTreeGeneratorAgent:
    """
    Agent responsible for generating Mermaid-formatted attack trees.
    
    Processes threat statements and creates structured attack trees with
    logical attack paths, proper dependencies, and Mermaid formatting.
    """
    
    def __init__(self, bedrock_client: BedrockClient):
        """
        Initialize the Attack Tree Generator Agent.
        
        Args:
            bedrock_client: Bedrock client for AI processing
        """
        self.bedrock_client = bedrock_client
        
        # Mermaid color scheme for different step types
        self.color_scheme = {
            AttackStepType.ATTACK: "#ff6b6b",      # Red for attack steps
            AttackStepType.MITIGATION: "#51cf66",   # Green for mitigations
            AttackStepType.GOAL: "#339af0",         # Blue for goals
            AttackStepType.FACT: "#ffd43b"          # Yellow for facts/conditions
        }
        
        # System prompt for attack tree generation
        self.system_prompt = """You are a cybersecurity expert that generates detailed attack trees from threat statements.

Your task is to analyze a threat statement and create a structured attack tree showing:
1. The main attack goal
2. Logical attack steps and sub-steps
3. Prerequisites and conditions
4. Alternative attack paths
5. Potential mitigations

Respond with a JSON object containing:
{
    "attack_goal": "Main goal of the attack",
    "attack_steps": [
        {
            "id": "unique_step_id",
            "description": "Step description",
            "type": "attack|mitigation|goal|fact",
            "dependencies": ["list_of_prerequisite_step_ids"],
            "likelihood": "low|medium|high",
            "impact": "low|medium|high"
        }
    ],
    "attack_paths": [
        {
            "path_id": "path_1",
            "description": "Path description",
            "steps": ["step_id_1", "step_id_2"],
            "likelihood": "low|medium|high",
            "impact": "low|medium|high"
        }
    ],
    "mitigations": [
        {
            "id": "mitigation_id",
            "description": "Mitigation description",
            "effectiveness": "low|medium|high",
            "mitigates_steps": ["step_id_1", "step_id_2"]
        }
    ]
}

Guidelines:
- Create realistic, technically accurate attack steps
- Include both technical and social engineering vectors where applicable
- Consider the specific context provided (technologies, sector, etc.)
- Generate 5-15 attack steps for comprehensive coverage
- Include at least 2-3 alternative attack paths
- Suggest relevant mitigations for key attack steps
- Use clear, concise descriptions"""
    
    def generate_attack_tree(
        self,
        threat_statement: ThreatStatement,
        context_info: Optional[ContextInformation] = None
    ) -> GenerationResult:
        """
        Generate an attack tree from a threat statement.
        
        Args:
            threat_statement: The threat statement to process
            context_info: Optional context information for better generation
            
        Returns:
            GenerationResult with attack tree or error information
        """
        start_time = datetime.now()
        
        logger.info(f"Generating attack tree for threat: {threat_statement.id}")
        
        # Check if threat meets severity threshold
        if not threat_statement.is_high_severity():
            logger.info(f"Skipping threat {threat_statement.id} - severity is {threat_statement.severity.value}, not high")
            return GenerationResult(
                attack_tree=None,
                generation_errors=[],
                generation_warnings=[],
                skipped_reason=f"Threat severity is {threat_statement.severity.value}, only processing high-severity threats",
                processing_time_seconds=0.0
            )
        
        generation_errors = []
        generation_warnings = []
        
        try:
            # Generate attack tree structure using AI
            attack_structure = self._generate_attack_structure(threat_statement, context_info)
            
            # Create attack steps from structure
            attack_steps = self._create_attack_steps(attack_structure)
            
            # Generate Mermaid diagram
            mermaid_content = self._generate_mermaid_diagram(attack_steps, attack_structure)
            
            # Create attack tree object
            attack_tree = AttackTree(
                threat_id=threat_statement.id,
                title=f"Attack Tree: {threat_statement.threat_action}",
                mermaid_content=mermaid_content,
                attack_steps=attack_steps,
                ttc_mappings={},  # Will be populated by TTC mapping agent
                generated_timestamp=datetime.now(),
                context_info=context_info
            )
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            logger.info(f"Successfully generated attack tree with {len(attack_steps)} steps")
            
            return GenerationResult(
                attack_tree=attack_tree,
                generation_errors=generation_errors,
                generation_warnings=generation_warnings,
                skipped_reason=None,
                processing_time_seconds=processing_time
            )
            
        except Exception as e:
            error_msg = f"Error generating attack tree: {e}"
            logger.error(error_msg)
            generation_errors.append(error_msg)
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return GenerationResult(
                attack_tree=None,
                generation_errors=generation_errors,
                generation_warnings=generation_warnings,
                skipped_reason=None,
                processing_time_seconds=processing_time
            )
    
    def _generate_attack_structure(
        self,
        threat_statement: ThreatStatement,
        context_info: Optional[ContextInformation]
    ) -> Dict[str, Any]:
        """
        Generate attack tree structure using AI.
        
        Args:
            threat_statement: The threat statement to analyze
            context_info: Optional context information
            
        Returns:
            Dictionary with attack tree structure
        """
        # Prepare context for AI
        context_text = self._prepare_context_text(threat_statement, context_info)
        
        prompt = f"""Analyze the following threat statement and generate a detailed attack tree:

THREAT STATEMENT:
- ID: {threat_statement.id}
- Severity: {threat_statement.severity.value}
- Threat Source: {threat_statement.threat_source}
- Prerequisites: {threat_statement.prerequisites}
- Threat Action: {threat_statement.threat_action}
- Threat Impact: {threat_statement.threat_impact}
- Impacted Assets: {', '.join(threat_statement.impacted_assets)}
- Impacted Goals: {', '.join(threat_statement.impacted_goals)}

CONTEXT:
{context_text}

Generate a comprehensive attack tree that shows how an attacker could achieve the threat action, including alternative paths and relevant mitigations."""
        
        try:
            response = self.bedrock_client.invoke_model(
                prompt=prompt,
                system_prompt=self.system_prompt,
                max_tokens=3000,
                temperature=0.2  # Lower temperature for more consistent structure
            )
            
            # Parse JSON response
            import json
            attack_structure = json.loads(response.content)
            
            # Validate structure
            self._validate_attack_structure(attack_structure)
            
            return attack_structure
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON response from AI: {e}")
        except BedrockClientError as e:
            raise ValueError(f"AI generation failed: {e}")
    
    def _prepare_context_text(
        self,
        threat_statement: ThreatStatement,
        context_info: Optional[ContextInformation]
    ) -> str:
        """Prepare context text for AI prompt."""
        context_parts = []
        
        if context_info:
            if context_info.technologies:
                context_parts.append(f"Technologies: {', '.join(context_info.technologies)}")
            
            if context_info.programming_languages:
                context_parts.append(f"Programming Languages: {', '.join(context_info.programming_languages)}")
            
            if context_info.sector:
                context_parts.append(f"Business Sector: {context_info.sector}")
            
            if context_info.architecture_type:
                context_parts.append(f"Architecture: {context_info.architecture_type}")
            
            if context_info.security_objectives:
                context_parts.append(f"Security Objectives: {', '.join(context_info.security_objectives)}")
        
        if not context_parts:
            context_parts.append("No specific context information available")
        
        return "\n".join(context_parts)
    
    def _validate_attack_structure(self, structure: Dict[str, Any]) -> None:
        """Validate the attack structure from AI."""
        required_fields = ["attack_goal", "attack_steps"]
        
        for field in required_fields:
            if field not in structure:
                raise ValueError(f"Missing required field: {field}")
        
        if not isinstance(structure["attack_steps"], list):
            raise ValueError("attack_steps must be a list")
        
        if len(structure["attack_steps"]) == 0:
            raise ValueError("attack_steps cannot be empty")
        
        # Validate each attack step
        for i, step in enumerate(structure["attack_steps"]):
            if not isinstance(step, dict):
                raise ValueError(f"Attack step {i} must be a dictionary")
            
            required_step_fields = ["id", "description", "type"]
            for field in required_step_fields:
                if field not in step:
                    raise ValueError(f"Attack step {i} missing required field: {field}")
    
    def _create_attack_steps(self, structure: Dict[str, Any]) -> List[AttackStep]:
        """Create AttackStep objects from the AI-generated structure."""
        attack_steps = []
        
        # Add the main goal as a step
        goal_step = AttackStep(
            id="goal_main",
            description=structure["attack_goal"],
            step_type=AttackStepType.GOAL,
            dependencies=[],
            ttc_reference=None
        )
        attack_steps.append(goal_step)
        
        # Process attack steps from AI
        for step_data in structure["attack_steps"]:
            try:
                # Map step type
                step_type_str = step_data["type"].lower()
                if step_type_str == "attack":
                    step_type = AttackStepType.ATTACK
                elif step_type_str == "mitigation":
                    step_type = AttackStepType.MITIGATION
                elif step_type_str == "goal":
                    step_type = AttackStepType.GOAL
                elif step_type_str == "fact":
                    step_type = AttackStepType.FACT
                else:
                    logger.warning(f"Unknown step type: {step_type_str}, defaulting to ATTACK")
                    step_type = AttackStepType.ATTACK
                
                # Create attack step
                attack_step = AttackStep(
                    id=step_data["id"],
                    description=step_data["description"],
                    step_type=step_type,
                    dependencies=step_data.get("dependencies", []),
                    ttc_reference=None
                )
                
                attack_steps.append(attack_step)
                
            except Exception as e:
                logger.warning(f"Error processing attack step {step_data.get('id', 'unknown')}: {e}")
                continue
        
        return attack_steps
    
    def _generate_mermaid_diagram(
        self,
        attack_steps: List[AttackStep],
        structure: Dict[str, Any]
    ) -> str:
        """Generate Mermaid diagram from attack steps."""
        lines = [
            "graph TD",
            ""
        ]
        
        # Add step definitions with styling
        for step in attack_steps:
            # Clean description for Mermaid (remove special characters)
            clean_desc = self._clean_mermaid_text(step.description)
            
            # Determine node shape based on step type
            if step.step_type == AttackStepType.GOAL:
                node_def = f'    {step.id}["{clean_desc}"]'
            elif step.step_type == AttackStepType.MITIGATION:
                node_def = f'    {step.id}{{{clean_desc}}}'  # Diamond shape for mitigations
            elif step.step_type == AttackStepType.FACT:
                node_def = f'    {step.id}("{clean_desc}")'  # Round shape for facts
            else:  # ATTACK
                node_def = f'    {step.id}["{clean_desc}"]'
            
            lines.append(node_def)
        
        lines.append("")
        
        # Add dependencies/connections
        for step in attack_steps:
            for dep_id in step.dependencies:
                lines.append(f"    {dep_id} --> {step.id}")
        
        # Add connections from attack paths if available
        if "attack_paths" in structure:
            for path in structure["attack_paths"]:
                path_steps = path.get("steps", [])
                for i in range(len(path_steps) - 1):
                    current_step = path_steps[i]
                    next_step = path_steps[i + 1]
                    # Only add if not already added via dependencies
                    connection = f"    {current_step} --> {next_step}"
                    if connection not in lines:
                        lines.append(connection)
        
        lines.append("")
        
        # Add styling
        lines.extend(self._generate_mermaid_styling(attack_steps))
        
        return "\n".join(lines)
    
    def _clean_mermaid_text(self, text: str) -> str:
        """Clean text for use in Mermaid diagrams."""
        # Remove or replace characters that can break Mermaid syntax
        text = text.replace('"', "'")
        text = text.replace('\n', ' ')
        text = text.replace('\r', ' ')
        text = re.sub(r'\s+', ' ', text)  # Collapse multiple spaces
        text = text.strip()
        
        # Truncate if too long
        if len(text) > 80:
            text = text[:77] + "..."
        
        return text
    
    def _generate_mermaid_styling(self, attack_steps: List[AttackStep]) -> List[str]:
        """Generate Mermaid styling for attack steps."""
        styling_lines = []
        
        # Group steps by type for styling
        step_groups = {}
        for step in attack_steps:
            step_type = step.step_type
            if step_type not in step_groups:
                step_groups[step_type] = []
            step_groups[step_type].append(step.id)
        
        # Apply styling for each group
        for step_type, step_ids in step_groups.items():
            color = self.color_scheme.get(step_type, "#cccccc")
            
            for step_id in step_ids:
                styling_lines.append(f"    style {step_id} fill:{color}")
        
        return styling_lines
    
    def generate_multiple_trees(
        self,
        threat_statements: List[ThreatStatement],
        context_info: Optional[ContextInformation] = None
    ) -> List[GenerationResult]:
        """
        Generate attack trees for multiple threat statements.
        
        Args:
            threat_statements: List of threat statements to process
            context_info: Optional context information
            
        Returns:
            List of GenerationResult objects
        """
        results = []
        
        logger.info(f"Generating attack trees for {len(threat_statements)} threat statements")
        
        for threat_statement in threat_statements:
            try:
                result = self.generate_attack_tree(threat_statement, context_info)
                results.append(result)
                
                if result.is_successful():
                    logger.info(f"Generated attack tree for threat {threat_statement.id}")
                elif result.skipped_reason:
                    logger.info(f"Skipped threat {threat_statement.id}: {result.skipped_reason}")
                else:
                    logger.error(f"Failed to generate attack tree for threat {threat_statement.id}")
                
            except Exception as e:
                logger.error(f"Unexpected error processing threat {threat_statement.id}: {e}")
                results.append(GenerationResult(
                    attack_tree=None,
                    generation_errors=[f"Unexpected error: {e}"],
                    generation_warnings=[],
                    skipped_reason=None,
                    processing_time_seconds=0.0
                ))
        
        successful_count = sum(1 for r in results if r.is_successful())
        skipped_count = sum(1 for r in results if r.skipped_reason)
        failed_count = len(results) - successful_count - skipped_count
        
        logger.info(f"Attack tree generation complete: {successful_count} successful, {skipped_count} skipped, {failed_count} failed")
        
        return results
    
    def save_attack_tree(
        self,
        attack_tree: AttackTree,
        output_directory: str,
        filename_prefix: str = "attack_tree"
    ) -> str:
        """
        Save an attack tree to a Mermaid file.
        
        Args:
            attack_tree: The attack tree to save
            output_directory: Directory to save the file
            filename_prefix: Prefix for the filename
            
        Returns:
            Path to the saved file
        """
        from pathlib import Path
        
        output_dir = Path(output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create filename
        safe_threat_id = re.sub(r'[^\w\-_]', '_', attack_tree.threat_id)
        filename = f"{filename_prefix}_{safe_threat_id}.mmd"
        output_file = output_dir / filename
        
        # Prepare content
        content_lines = [
            f"# Attack Tree: {attack_tree.title}",
            "",
            f"**Threat ID:** {attack_tree.threat_id}",
            f"**Generated:** {attack_tree.generated_timestamp.isoformat()}",
            f"**Steps:** {len(attack_tree.attack_steps)}",
            "",
            "## Mermaid Diagram",
            "",
            "```mermaid",
            attack_tree.mermaid_content,
            "```",
            "",
            "## Attack Steps",
            ""
        ]
        
        # Add step details
        for step in attack_tree.attack_steps:
            content_lines.extend([
                f"### {step.id} ({step.step_type.value})",
                "",
                step.description,
                ""
            ])
            
            if step.dependencies:
                content_lines.extend([
                    f"**Dependencies:** {', '.join(step.dependencies)}",
                    ""
                ])
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(content_lines))
            
            logger.info(f"Saved attack tree to: {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Error saving attack tree: {e}")
            raise
    
    def get_generation_statistics(self, results: List[GenerationResult]) -> Dict[str, Any]:
        """
        Get statistics about attack tree generation results.
        
        Args:
            results: List of generation results
            
        Returns:
            Dictionary with statistics
        """
        if not results:
            return {"total": 0}
        
        successful = [r for r in results if r.is_successful()]
        skipped = [r for r in results if r.skipped_reason]
        failed = [r for r in results if not r.is_successful() and not r.skipped_reason]
        
        total_processing_time = sum(r.processing_time_seconds for r in results)
        avg_processing_time = total_processing_time / len(results) if results else 0
        
        # Calculate step statistics for successful trees
        step_counts = [len(r.attack_tree.attack_steps) for r in successful if r.attack_tree]
        avg_steps = sum(step_counts) / len(step_counts) if step_counts else 0
        
        return {
            "total": len(results),
            "successful": len(successful),
            "skipped": len(skipped),
            "failed": len(failed),
            "success_rate": len(successful) / len(results) if results else 0,
            "total_processing_time_seconds": total_processing_time,
            "average_processing_time_seconds": avg_processing_time,
            "average_steps_per_tree": avg_steps,
            "min_steps": min(step_counts) if step_counts else 0,
            "max_steps": max(step_counts) if step_counts else 0
        }