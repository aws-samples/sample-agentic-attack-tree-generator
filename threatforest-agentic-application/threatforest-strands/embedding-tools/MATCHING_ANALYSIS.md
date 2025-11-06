# Attack Step Matching Analysis

## Current Implementation

### Baseline Approach
- **Similarity Metric**: Cosine similarity
- **Model**: `sentence-transformers/all-mpnet-base-v2` (768-dim)
- **Method**: Semantic embedding matching
- **Top-K**: Returns 3 best matches per attack step

### Why Cosine Similarity?
✅ **Appropriate for:**
- Normalized embeddings (sentence-transformers output)
- Semantic similarity in high-dimensional spaces
- Fast computation with sklearn
- Direction matters more than magnitude

## Test Results Summary

### Model Comparison (from comparison.md)

| Query | Best Model | Technique | Similarity |
|-------|-----------|-----------|------------|
| Steal credentials from memory | **Qwen 0.6B** | T1552 Unsecured Credentials | 0.640 |
| Execute malicious code remotely | **Qwen 0.6B** | T1021 Remote Services | 0.551 |
| Escalate privileges using vulnerability | **Qwen 0.6B** | T1548 Abuse Elevation Control | 0.661 |
| Exfiltrate data over encrypted channel | **Qwen 4B** | T1567 Exfiltration Over Web Service | 0.668 |

**Winner**: Qwen 0.6B - Best balance of accuracy and performance

### Observed Issues

1. **Low confidence matches** (< 0.3 similarity)
   - Example: "Pivot to HealthLake" → 0.229
   - Indicates semantic mismatch

2. **Generic over specific**
   - "Query FHIR data repository" → Generic T1213 instead of AWS-specific AT1023.001

3. **No domain weighting**
   - AWS-specific terms not prioritized

## Improvement Approaches

### 1. Model Upgrade ⭐ RECOMMENDED
**Change**: Switch to Qwen 0.6B
**Impact**: +8-13% similarity improvement
**Effort**: Minimal (one line change)

```python
model = SentenceTransformer('Qwen/Qwen3-Embedding-0.6B')
```

### 2. Domain-Specific Weighting
**Change**: Boost AWS/cloud term matches
**Impact**: Better AWS technique prioritization
**Effort**: Low

Boost score when both attack step and technique contain:
- AWS service names (S3, EC2, IAM, Lambda, etc.)
- Cloud-specific terms (bucket, instance, role, etc.)

### 3. Hybrid Keyword Fallback
**Change**: Use exact matching for low-confidence results
**Impact**: Catch obvious matches that embeddings miss
**Effort**: Medium

When similarity < 0.3, try:
- Technique ID extraction (T1234, AT1234)
- Service name matching
- Exact phrase matching

### 4. Multi-Signal Re-ranking
**Change**: Combine multiple scoring factors
**Impact**: More nuanced ranking
**Effort**: Medium

Factors:
- Embedding similarity (primary)
- Technique ID prefix (AT = Amazon-specific)
- Kill chain phase alignment
- Term overlap

### 5. Alternative Similarity Metrics
**Change**: Test other distance functions
**Impact**: Potentially better for specific cases
**Effort**: Low

Options:
- Euclidean distance: `1 / (1 + euclidean(v1, v2))`
- Dot product: `np.dot(v1, v2)` (for normalized vectors)
- Manhattan distance: Less sensitive to outliers

## Implementation Priority

1. **Immediate**: Switch to Qwen 0.6B (proven improvement)
2. **Short-term**: Add domain weighting (AWS terms)
3. **Medium-term**: Implement hybrid fallback
4. **Optional**: Test alternative metrics

## Evaluation Metrics

### Quantitative
- **Similarity score distribution**: Target > 0.4 for good matches
- **Top-1 accuracy**: Manual validation of best match
- **Coverage**: % of steps with similarity > 0.3

### Qualitative
- **Semantic correctness**: Does match make sense?
- **Specificity**: AWS-specific over generic when applicable
- **Kill chain alignment**: Matches appropriate attack phase

## Testing Approach

Run `test_matching_improvements.py` to compare:
1. Baseline (mpnet + cosine)
2. Qwen 0.6B + cosine
3. Qwen 0.6B + domain weighting
4. Qwen 0.6B + hybrid approach
5. Alternative metrics

Each approach tested on:
- Sample queries (4 test cases)
- Real attack steps from attack trees
- Edge cases (low similarity scenarios)

## Recommendations

**For production use:**
1. Use Qwen 0.6B as base model
2. Add domain weighting for AWS terms
3. Set minimum similarity threshold: 0.35
4. Return top-3 matches with confidence scores
5. Flag low-confidence matches (< 0.35) for manual review

**Confidence levels:**
- **High** (> 0.5): Excellent match, use directly
- **Medium** (0.35-0.5): Good match, review recommended
- **Low** (< 0.35): Manual mapping required
