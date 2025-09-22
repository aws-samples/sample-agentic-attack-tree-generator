# Requirements Document

## Introduction

ThreatForest (TF) is a Python command-line application that automatically generates attack trees from threat statements found in application context files. The application analyzes existing documentation (READMEs, architecture diagrams, Data Flow Diagrams, and Threat Statements) to extract key information, validates this with the user, and generates Mermaid-formatted attack trees for high-severity threats. It also maps attack steps to MITRE ATT&CK techniques using STIX-formatted data.

## Requirements

### Requirement 1

**User Story:** As a security analyst, I want to launch ThreatForest from my terminal within an application directory, so that I can analyze the application's security posture without complex setup.

#### Acceptance Criteria

1. WHEN the user runs TF from a terminal THEN the system SHALL launch from the current working directory
2. WHEN TF is launched THEN the system SHALL scan the current directory for context files
3. IF TF is not run from a directory containing an application THEN the system SHALL display an appropriate error message

### Requirement 2

**User Story:** As a security analyst, I want TF to automatically detect and parse context files, so that I don't have to manually specify input files.

#### Acceptance Criteria

1. WHEN TF scans a directory THEN the system SHALL check for README files, architecture diagrams, Data Flow Diagrams, and Threat Statements
2. IF required context files are missing THEN the system SHALL notify the user which files are needed
3. WHEN context files are found THEN the system SHALL parse them to extract relevant information
4. IF context files contain insufficient data THEN the system SHALL inform the user what additional information is required

### Requirement 3

**User Story:** As a security analyst, I want TF to extract and validate key application information with me, so that the generated attack trees are accurate and relevant.

#### Acceptance Criteria

1. WHEN TF processes context files THEN the system SHALL extract technologies, programming languages, sector, and security objectives
2. WHEN key information is extracted THEN the system SHALL present it to the user for validation
3. WHEN the user validates information THEN the system SHALL save the validated data to a separate .md file
4. IF the user rejects extracted information THEN the system SHALL allow manual correction of the data
5. WHEN information is saved THEN the system SHALL use consistent formatting in the output .md file

### Requirement 4

**User Story:** As a security analyst, I want TF to generate attack trees only for high-severity threats, so that I can focus on the most critical security risks.

#### Acceptance Criteria

1. WHEN TF parses threat statements THEN the system SHALL identify the severity level of each threat
2. WHEN threat severity is determined THEN the system SHALL only process threats marked as "High"
3. WHEN generating attack trees THEN the system SHALL use Mermaid format as specified in mermaid-prompt.md
4. WHEN an attack tree is generated THEN the system SHALL save it as a separate file with appropriate naming
5. IF no high-severity threats are found THEN the system SHALL notify the user accordingly

### Requirement 5

**User Story:** As a security analyst, I want TF to map attack steps to MITRE ATT&CK techniques, so that I can understand the specific tactics and techniques involved in each attack path.

#### Acceptance Criteria

1. WHEN processing attack steps THEN the system SHALL search aaf-bundle.json for matching STIX techniques
2. WHEN analyzing attack steps THEN the system SHALL only apply TTC mapping when there is >80% conceptual alignment
3. WHEN a strong match is found THEN the system SHALL incorporate TTC reference and data into the attack step
4. WHEN TTC mapping is applied THEN the system SHALL update the attack tree with the enhanced information
5. IF no suitable TTC match is found THEN the system SHALL leave the attack step unchanged

### Requirement 6

**User Story:** As a security analyst, I want TF to generate a summary report, so that I can quickly review all threat statements and their corresponding attack trees.

#### Acceptance Criteria

1. WHEN all attack trees are generated THEN the system SHALL create a summary .md file
2. WHEN creating the summary THEN the system SHALL list all processed threat statements
3. WHEN listing threat statements THEN the system SHALL include links to applicable attack trees
4. WHEN the summary is complete THEN the system SHALL save it with a clear, descriptive filename
5. IF no attack trees were generated THEN the system SHALL still create a summary explaining why

### Requirement 7

**User Story:** As a security analyst, I want TF to handle errors gracefully, so that I can understand and resolve issues when they occur.

#### Acceptance Criteria

1. WHEN TF encounters file parsing errors THEN the system SHALL display clear error messages
2. WHEN LLM API calls fail THEN the system SHALL retry with exponential backoff up to 3 times
3. WHEN STIX file parsing fails THEN the system SHALL continue processing without TTC mapping
4. WHEN invalid Mermaid syntax is generated THEN the system SHALL validate and correct the output
5. IF critical errors occur THEN the system SHALL log detailed error information for debugging