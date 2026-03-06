"""Shared embedding service — thin re-export from existing implementation.

The actual EmbeddingService lives in modules/graph/embedding_service.py.
This module re-exports it so new graph agents import from embedding/ instead
of reaching into modules/graph/ directly.
"""

from threatforest.modules.graph.embedding_service import EmbeddingService

__all__ = ["EmbeddingService"]
