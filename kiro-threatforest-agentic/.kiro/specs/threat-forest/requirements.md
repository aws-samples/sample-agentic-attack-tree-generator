# Requirements Document

## Introduction

ThreatForest (TF) is an agentic AI application that automatically generates attack trees from threat statements using the Strand framework. The application analyzes application context files, extracts key security information, and produces Mermaid-formatted attack trees enhanced with STIX-formatted threat intelligence from the AAF bundle. TF operates as a multi-agent system orchestrated through a command-line interface, providing security analysts with automated threat modeling capabilities.

## Requirements

### Requirement 1

**User Story:** As a security analyst, I want to launch ThreatForest from my terminal or IDE within an application directory, so that I can initiate automated threat analysis for the current project.

#### Acceptance Criteria

1. WHEN the user runs the TF command from a terminal THEN the system SHALL start the orchestrator agent
2. WHEN the user launches TF from an IDE THEN the system SHALL integrate with the IDE environment and start the orchestrator agent
3. WHEN TF starts THEN the system SHALL scan the current directory for application files to analyze
4. IF the user provides a Bedrock API key THEN the system SHALL authenticate and initialize the AI agents
5. WHEN TF launches successfully THEN the system SHALL display a status message confirming the orchestrator agent is running

### Requirement 2

**User Story:** As a security analyst, I want ThreatForest to automatically detect and analyze context files in my application directory, so that I can ensure all relevant security documentation is considered.

#### Acceptance Criteria

1. WHEN the context detection agent runs THEN the system SHALL scan for README files, architecture diagrams, data flow diagrams, and threat statements
2. WHEN context files are found THEN the system SHALL validate that they contain required security data
3. IF required context files are missing THEN the system SHALL notify the user and provide guidance on required file formats
4. WHEN context files are validated THEN the system SHALL pass them to the information extraction agent
5. WHEN context scanning completes THEN the system SHALL log which files were found and processed

### Requirement 3

**User Story:** As a security analyst, I want ThreatForest to extract and validate key security information from my context files, so that I can ensure accurate threat modeling inputs.

#### Acceptance Criteria

1. WHEN the information extraction agent processes context files THEN the system SHALL identify technologies, programming languages, and sector information
2. WHEN extracting information THEN the system SHALL determine security objectives (Confidentiality, Integrity, Availability)
3. WHEN key information is extracted THEN the system SHALL present it to the user for validation
4. IF the user approves the extracted information THEN the system SHALL save it to a separate .md file
5. IF the user rejects or modifies information THEN the system SHALL update the extraction and re-validate
6. WHEN information is validated THEN the system SHALL proceed to attack tree generation

### Requirement 4

**User Story:** As a security analyst, I want ThreatForest to generate attack trees only for high-severity threats, so that I can focus on the most critical security risks.

#### Acceptance Criteria

1. WHEN the attack tree generation agent processes threat statements THEN the system SHALL parse severity levels (low, medium, high)
2. WHEN threat severity is determined THEN the system SHALL only generate attack trees for threats marked as "High"
3. WHEN generating attack trees THEN the system SHALL format them in Mermaid syntax according to the provided template
4. WHEN an attack tree is generated THEN the system SHALL save it as a separate file with appropriate naming
5. IF no high-severity threats exist THEN the system SHALL notify the user and provide a summary of available threats

### Requirement 5

**User Story:** As a security analyst, I want ThreatForest to enhance attack trees with STIX threat intelligence, so that I can have more detailed and standardized threat information.

#### Acceptance Criteria

1. WHEN the TTC mapping agent processes attack steps THEN the system SHALL search the aaf-bundle.json file for relevant tactics and techniques
2. WHEN analyzing attack steps THEN the system SHALL use semantic alignment to match steps with TTC techniques
3. WHEN semantic alignment exceeds 80% THEN the system SHALL apply the TTC mapping to the attack step
4. WHEN TTC mapping is applied THEN the system SHALL incorporate TTC reference data into the attack step
5. WHEN attack trees are enhanced THEN the system SHALL update the Mermaid format to include TTC information
6. IF no strong TTC alignment is found THEN the system SHALL leave the attack step unchanged

### Requirement 6

**User Story:** As a security analyst, I want ThreatForest to provide a comprehensive summary of generated attack trees, so that I can quickly review and navigate the threat analysis results.

#### Acceptance Criteria

1. WHEN all attack trees are generated THEN the system SHALL create a summary .md file
2. WHEN creating the summary THEN the system SHALL list all processed threat statements with their severity levels
3. WHEN listing threats THEN the system SHALL provide links to applicable attack tree files
4. WHEN the summary is complete THEN the system SHALL include metadata about the analysis (timestamp, file counts, etc.)
5. WHEN TF completes processing THEN the system SHALL display the summary file location to the user

### Requirement 7

**User Story:** As a security analyst, I want ThreatForest to handle errors gracefully and provide clear feedback, so that I can troubleshoot issues and ensure reliable operation.

#### Acceptance Criteria

1. WHEN API authentication fails THEN the system SHALL display clear error messages and suggest remediation steps
2. WHEN required files are missing or malformed THEN the system SHALL provide specific guidance on file requirements
3. WHEN agent processing fails THEN the system SHALL log detailed error information and continue with remaining tasks where possible
4. WHEN STIX file parsing fails THEN the system SHALL notify the user and continue attack tree generation without TTC enhancement
5. WHEN any critical error occurs THEN the system SHALL save partial results and provide recovery options

### Requirement 8

**User Story:** As a security analyst, I want ThreatForest to be configurable for different environments and use cases, so that I can adapt it to various project requirements.

#### Acceptance Criteria

1. WHEN TF starts THEN the system SHALL support configuration via command-line arguments and configuration files
2. WHEN configuring TF THEN the system SHALL allow customization of file patterns, severity thresholds, and output formats
3. WHEN using different Bedrock regions THEN the system SHALL support region-specific API endpoints
4. WHEN processing different project types THEN the system SHALL adapt context file detection patterns
5. WHEN generating outputs THEN the system SHALL support configurable output directory structures