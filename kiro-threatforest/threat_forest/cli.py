"""
Command-line interface for ThreatForest application.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .config import ConfigManager
from .orchestrator import ThreatForestOrchestrator
from .utils import setup_logging, get_logger
from .exceptions import ThreatForestError


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="threat-forest",
        description="Generate attack trees from threat statements with MITRE ATT&CK mappings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  threat-forest                    # Analyze current directory (uses AWS Bedrock)
  threat-forest /path/to/project   # Analyze specific directory
  threat-forest --config config.yaml --log-level DEBUG
  threat-forest --output-dir ./security-analysis

Prerequisites:
  - AWS credentials configured (aws configure, environment variables, or IAM roles)
  - Access to Amazon Bedrock in your AWS region
        """
    )
    
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Directory containing application context files (default: current directory)"
    )
    
    parser.add_argument(
        "--output-dir",
        default="threat_forest_output",
        help="Output directory for generated files (default: threat_forest_output)"
    )
    
    parser.add_argument(
        "--config",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--no-user-validation",
        action="store_true",
        help="Skip user validation of extracted information"
    )
    
    parser.add_argument(
        "--high-threats-only",
        action="store_true",
        default=True,
        help="Process only high-severity threats (default: True)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0"
    )
    
    return parser


def main() -> int:
    """Main entry point for the CLI application."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Set up logging
    log_file = Path(args.output_dir) / "logs" / "threat_forest.log"
    setup_logging(args.log_level, str(log_file))
    logger = get_logger(__name__)
    
    try:
        # Validate input directory
        input_dir = Path(args.directory).resolve()
        if not input_dir.exists():
            logger.error(f"Directory does not exist: {input_dir}")
            return 1
        
        if not input_dir.is_dir():
            logger.error(f"Path is not a directory: {input_dir}")
            return 1
        
        logger.info(f"Starting ThreatForest analysis of: {input_dir}")
        logger.info(f"Output directory: {args.output_dir}")
        
        # Load configuration
        config_manager = ConfigManager(args.config)
        config = config_manager.load_config()
        
        # Create orchestrator and run analysis
        orchestrator = ThreatForestOrchestrator(
            input_directory=str(input_dir),
            output_directory=args.output_dir,
            config=config,
            skip_user_validation=args.no_user_validation,
            high_threats_only=args.high_threats_only
        )
        
        success = orchestrator.run()
        
        if success:
            logger.info("ThreatForest analysis completed successfully!")
            return 0
        else:
            logger.error("ThreatForest analysis failed")
            return 1
            
    except ThreatForestError as e:
        logger.error(f"ThreatForest error: {e}")
        return 1
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        return 1
    except Exception as e:
        logger.critical(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())