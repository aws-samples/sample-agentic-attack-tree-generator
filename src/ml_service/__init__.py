"""ThreatForest ML service.

A standalone FastAPI app that isolates the Python-only ML/MITRE layer
(ATTACK-BERT embeddings via sentence-transformers + STIX vector search) behind
an HTTP seam. The TypeScript agent pipeline (WS-3) calls this service for the
TTP stage instead of importing the ML code in-process.

Why a separate process rather than a mounted router on the main server:
the embedding model + STIX graphs are loaded once at startup and held warm for
the life of the process, and that runtime stays Python regardless of the rest of
the stack moving to TypeScript. Keeping it standalone lets the TS engine own the
main server while this stays a focused, independently-deployable Python service.
"""

from ml_service.app import app, create_app

__all__ = ["app", "create_app"]
