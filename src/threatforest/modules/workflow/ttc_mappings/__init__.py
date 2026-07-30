"""TTC Mappings — matcher for embedding-based technique matching.

Only `TTCMatcher` is exported: it backs the ML service's `/match_steps`. The old
`MitigationMapper` went with the legacy pipeline — the TS side intentionally does
not duplicate STIX-derived mitigations (see the note in
`ts/packages/server/src/routes/applications.ts`).
"""
from .matcher import TTCMatcher

__all__ = ["TTCMatcher"]
