# STIX Threat Intelligence Mapping Recommendations

## Problem
Map attack steps from ThreatForest-generated attack trees to real-world threat techniques in STIX data (CSV files converted from JSON).

## Recommended Approaches

### 1. **Hybrid Embeddings + Keyword Matching** (Best Balance)
- Create embeddings for attack step descriptions and STIX technique summaries
- Use cosine similarity for semantic matching
- Add keyword/regex fallback for exact technique IDs or names
- Most accurate for varied attack descriptions

### 2. **MITRE ATT&CK ID Bridging** (Simplest)
- Your app already maps to MITRE techniques
- Create lookup table: `MITRE_ID -> STIX_techniques`
- Fast, reliable, leverages existing mapping
- Limited to techniques already in MITRE framework

### 3. **Lightweight Vector Search** (Scalable)
- Use sentence-transformers for local embeddings
- Index STIX technique descriptions
- Query with attack step text
- Good performance without external dependencies

## Implementation Recommendations

**Start with approach #2** (MITRE bridging) since your app already does MITRE mapping. Then enhance with embeddings for unmapped techniques.

**For embeddings**: Use `sentence-transformers/all-MiniLM-L6-v2` - it's lightweight, fast, and good for short technical descriptions.

**Context management**: Process STIX data in chunks, create summary embeddings rather than full-text embeddings to avoid context overflow.
