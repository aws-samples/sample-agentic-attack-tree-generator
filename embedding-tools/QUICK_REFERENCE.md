# Matching Improvements - Quick Reference

## TL;DR

✅ **Cosine similarity is appropriate** - works well with normalized embeddings  
✅ **Qwen 0.6B is better than mpnet** - 8-13% improvement  
✅ **Domain weighting helps AWS queries** - 10-20% boost for AWS-specific matches  
✅ **Use improved script** - `match_attack_steps_improved.py`

## What Changed

### Before (Baseline)
- Model: `all-mpnet-base-v2`
- Metric: Cosine similarity
- No domain-specific weighting
- Average similarity: 0.670

### After (Improved)
- Model: `Qwen/Qwen3-Embedding-0.6B`
- Metric: Cosine similarity + AWS term boosting
- Domain weighting for cloud terms
- Average similarity: 0.708 (+5.7%)
- Confidence levels added

## Usage

### Run Improved Matching
```bash
python match_attack_steps_improved.py
```

### Test All Approaches
```bash
python test_matching_improvements.py
```

## Confidence Levels

| Level | Similarity | Action |
|-------|-----------|--------|
| 🟢 High | > 0.7 | Use directly |
| 🟡 Medium | 0.5-0.7 | Review recommended |
| 🔴 Low | 0.35-0.5 | Manual validation |
| ⚫ Poor | < 0.35 | Requires manual mapping |

## Key Findings

1. **Cosine similarity is fit for purpose**
   - Best for normalized embeddings
   - Dot product gives identical results
   - Euclidean/Manhattan offer no advantage

2. **Qwen 0.6B outperforms mpnet**
   - Higher similarity scores across all queries
   - Better semantic understanding
   - Faster inference

3. **Domain weighting significantly helps**
   - AWS-specific queries: +10-20% similarity
   - Generic queries: unchanged
   - No performance penalty

4. **Multi-signal re-ranking works but needs validation**
   - Boosts Amazon-specific techniques (AT prefix)
   - May over-prioritize in some cases
   - Use with caution

## Files

- `MATCHING_ANALYSIS.md` - Full analysis and methodology
- `TEST_RESULTS.md` - Detailed test results and data
- `test_matching_improvements.py` - Test suite
- `match_attack_steps_improved.py` - Production implementation
- `QUICK_REFERENCE.md` - This file

## Next Steps

1. ✅ Testing complete
2. ⏭️ Update production to use Qwen 0.6B + domain weighting
3. ⏭️ Validate on full attack tree dataset
4. ⏭️ Consider multi-signal re-ranking (with validation)

## Questions?

See `MATCHING_ANALYSIS.md` for detailed methodology and `TEST_RESULTS.md` for complete test data.
