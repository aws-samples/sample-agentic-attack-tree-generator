# Implementation Plan

- [x] 1. Add model discovery methods to existing BedrockClient
  - Add `list_available_models()` method using Bedrock's ListFoundationModels API
  - Add `validate_model_region_compatibility()` method with verbose logging
  - Add `get_model_recommendations()` method for use case-based suggestions
  - Implement simple in-memory caching for model information (avoid over-engineering)
  - Add comprehensive logging for all model discovery operations
  - Write unit tests for new model discovery methods only
  - _Requirements: 2.1, 2.2, 2.3_

- [x] 2. Extend existing BedrockConfig with new parameters
  - Add temperature, max_tokens, top_p fields to existing BedrockConfig class
  - Add custom_parameters dict field for advanced users
  - Add validation_status and last_validated fields for tracking
  - Ensure backward compatibility with existing config files
  - Add verbose logging for configuration loading and validation
  - Write unit tests for new configuration fields only
  - _Requirements: 4.1, 4.2, 4.3_

- [x] 3. Create simple configuration validator using existing test_connection
  - Add `validate_configuration()` method to existing ConfigManager class
  - Leverage existing BedrockClient.test_connection() method for validation
  - Add AWS credential detection using boto3 session validation
  - Add verbose logging for each validation step with clear success/failure messages
  - Generate simple, actionable error messages for common issues
  - Write unit tests for validation scenarios using existing patterns
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 4. Build simple interactive setup wizard
  - Create `setup_wizard.py` module with basic step-by-step flow
  - Use existing Rich console patterns from CLI for consistent UI
  - Implement AWS credential detection using boto3 session checks
  - Add model selection using new model discovery methods from task 1
  - Use existing ConfigManager.save_config() for persistence
  - Add verbose logging for each setup step
  - Write unit tests with mocked Rich prompts
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [x] 5. Add new CLI commands to existing cli.py
  - Add `tf setup` command using existing Click patterns and Rich console
  - Add `tf config model` command for model selection
  - Add `tf config validate` command using validation from task 3
  - Enhance existing `tf config show` command with validation status
  - Use existing CLI error handling patterns and Rich formatting
  - Add verbose logging for all CLI operations
  - Write CLI tests using existing test patterns
  - _Requirements: 1.1, 2.1, 3.1, 4.3, 5.2_

- [x] 6. Enhance existing status command with configuration validation
  - Extend existing `tf status` command to include configuration validation
  - Use validation methods from task 3 to check configuration health
  - Add model availability checks using methods from task 1
  - Display validation results using existing Rich table formatting
  - Add verbose logging for status checks
  - Write tests extending existing status command tests
  - _Requirements: 3.1, 3.2, 3.3_

- [x] 7. Add configuration validation to existing CLI initialization
  - Modify existing `ThreatForestCLI.load_config()` method to include validation
  - Add optional validation step before analysis operations
  - Use existing error handling patterns for configuration issues
  - Add verbose logging for configuration loading and validation
  - Ensure backward compatibility with existing workflows
  - Write tests for enhanced configuration loading
  - _Requirements: 3.1, 3.2, 3.3_

- [x] 8. Create simple integration tests for new functionality
  - Write integration tests for setup wizard workflow
  - Test model discovery and selection flows
  - Test configuration validation scenarios
  - Use existing test patterns and fixtures where possible
  - Add verbose logging to integration tests for debugging
  - Focus on happy path and common error scenarios
  - _Requirements: All requirements integration testing_

- [x] 9. Update CLI help text and add logging configuration
  - Update help text for new commands using existing Click patterns
  - Add verbose logging configuration option to CLI
  - Enhance existing error messages with configuration guidance
  - Add examples to command help text
  - Ensure consistent messaging across all CLI commands
  - Test help text and logging output
  - _Requirements: 1.1, 1.5, 2.5, 3.5_