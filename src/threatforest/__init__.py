"""
ThreatForest - AI-Driven Threat Modeling & Attack Tree Generation

Copyright 2024 Cristian Leo, Danny Cortegaca, Anton Dykyi
Licensed under the Apache License 2.0
"""

__version__ = "1.0.0"
__author__ = "Cristian Leo, Danny Cortegaca, Anton Dykyi"
__license__ = "Apache-2.0"

# Deliberately no imports here. The pipeline is TypeScript; the only Python that
# ships is the ML service (`src/ml_service`), which imports
# `threatforest.{config, embedding.service, modules.workflow.ttc_mappings}`.
# This module previously did `from .cli import main`, which meant importing
# ANYTHING under `threatforest` executed the whole legacy pipeline (and the old
# FastAPI server, via modules/cli/runner.py). Keep this file side-effect free so
# the ML service's import closure stays small.

__all__ = ["__version__"]
