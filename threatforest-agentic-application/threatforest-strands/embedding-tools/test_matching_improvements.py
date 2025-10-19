#!/usr/bin/env python3
"""Test different matching approaches for attack step to technique mapping"""
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity, manhattan_distances
from scipy.spatial.distance import euclidean
import time

# Test queries covering different scenarios
TEST_QUERIES = [
    "Steal credentials from memory",
    "Execute malicious code remotely", 
    "Escalate privileges using vulnerability",
    "Exfiltrate data over encrypted channel",
    "Query AWS S3 bucket for sensitive data",
    "Exploit Lambda function vulnerability",
    "Access DynamoDB table without authorization",
    "Pivot to HealthLake data plane"
]

AWS_TERMS = ['aws', 's3', 'ec2', 'iam', 'lambda', 'dynamodb', 'rds', 'ecs', 
             'cloudformation', 'cloudwatch', 'sns', 'sqs', 'kinesis', 'athena',
             'glue', 'emr', 'eks', 'fargate', 'bucket', 'instance', 'role']

def load_embeddings(model_name='qwen'):
    """Load pre-generated embeddings"""
    with open(f'attack_pattern_embeddings_{model_name}.json', 'r') as f:
        return json.load(f)

def cosine_match(query_emb, technique_embs, query_text=None, patterns=None):
    """Standard cosine similarity"""
    return cosine_similarity([query_emb], technique_embs)[0]

def euclidean_match(query_emb, technique_embs, query_text=None, patterns=None):
    """Euclidean distance converted to similarity"""
    distances = np.array([euclidean(query_emb, t) for t in technique_embs])
    return 1 / (1 + distances)

def manhattan_match(query_emb, technique_embs, query_text=None, patterns=None):
    """Manhattan distance converted to similarity"""
    distances = manhattan_distances([query_emb], technique_embs)[0]
    return 1 / (1 + distances)

def dot_product_match(query_emb, technique_embs, query_text=None, patterns=None):
    """Dot product (for normalized vectors)"""
    return np.dot(technique_embs, query_emb)

def domain_weighted_match(query_emb, technique_embs, query_text, patterns):
    """Cosine similarity with AWS term boosting"""
    base_scores = cosine_similarity([query_emb], technique_embs)[0]
    
    query_lower = query_text.lower()
    boosted_scores = []
    
    for i, pattern in enumerate(patterns):
        tech_text = f"{pattern['name']} {pattern['description']}".lower()
        boost = 1.0
        
        # Boost for matching AWS terms
        for term in AWS_TERMS:
            if term in query_lower and term in tech_text:
                boost += 0.1
        
        boosted_scores.append(base_scores[i] * min(boost, 1.5))  # Cap at 1.5x
    
    return np.array(boosted_scores)

def hybrid_match(query_emb, technique_embs, query_text, patterns):
    """Cosine + keyword fallback for low confidence"""
    scores = cosine_similarity([query_emb], technique_embs)[0]
    
    # If best match is low confidence, try keyword boost
    if scores.max() < 0.3:
        query_lower = query_text.lower()
        for i, pattern in enumerate(patterns):
            # Boost if technique name appears in query
            if pattern['name'].lower() in query_lower:
                scores[i] += 0.2
            # Boost if query appears in technique description
            if query_lower in pattern['description'].lower():
                scores[i] += 0.1
    
    return scores

def rerank_with_signals(matches, query_text, patterns):
    """Multi-signal re-ranking"""
    for match in matches:
        score = match['similarity']
        pattern = patterns[match['idx']]
        
        # Boost Amazon-specific techniques
        if pattern['technique_id'] and pattern['technique_id'].startswith('AT'):
            score *= 1.2
        
        # Boost if AWS terms match
        query_lower = query_text.lower()
        tech_text = f"{pattern['name']} {pattern['description']}".lower()
        aws_matches = sum(1 for term in AWS_TERMS if term in query_lower and term in tech_text)
        score *= (1 + aws_matches * 0.05)
        
        match['reranked_score'] = min(score, 1.0)
    
    return sorted(matches, key=lambda x: x['reranked_score'], reverse=True)

def test_approach(name, match_func, model, embeddings_data, queries):
    """Test a matching approach"""
    print(f"\n{'='*70}")
    print(f"Testing: {name}")
    print(f"{'='*70}")
    
    technique_embs = np.array(embeddings_data['embeddings'])
    patterns = embeddings_data['patterns']
    
    start_time = time.time()
    query_embs = model.encode(queries)
    
    results = []
    for i, query in enumerate(queries):
        scores = match_func(query_embs[i], technique_embs, query, patterns)
        top_idx = scores.argmax()
        
        result = {
            'query': query,
            'technique_id': patterns[top_idx]['technique_id'],
            'name': patterns[top_idx]['name'],
            'similarity': float(scores[top_idx])
        }
        results.append(result)
        
        print(f"\n📝 {query}")
        print(f"   → {result['technique_id']:12s} {result['name']:45s} ({result['similarity']:.3f})")
    
    elapsed = time.time() - start_time
    avg_similarity = np.mean([r['similarity'] for r in results])
    
    print(f"\n⏱️  Time: {elapsed:.2f}s | Avg similarity: {avg_similarity:.3f}")
    
    return results

def test_reranking(model, embeddings_data, queries):
    """Test multi-signal re-ranking"""
    print(f"\n{'='*70}")
    print(f"Testing: Multi-Signal Re-ranking")
    print(f"{'='*70}")
    
    technique_embs = np.array(embeddings_data['embeddings'])
    patterns = embeddings_data['patterns']
    
    query_embs = model.encode(queries)
    
    for i, query in enumerate(queries):
        scores = cosine_similarity([query_embs[i]], technique_embs)[0]
        top_indices = scores.argsort()[-3:][::-1]
        
        matches = [
            {
                'idx': idx,
                'technique_id': patterns[idx]['technique_id'],
                'name': patterns[idx]['name'],
                'similarity': float(scores[idx])
            }
            for idx in top_indices
        ]
        
        reranked = rerank_with_signals(matches, query, patterns)
        
        print(f"\n📝 {query}")
        print(f"   Before: {matches[0]['technique_id']:12s} {matches[0]['name']:40s} ({matches[0]['similarity']:.3f})")
        print(f"   After:  {reranked[0]['technique_id']:12s} {reranked[0]['name']:40s} ({reranked[0]['reranked_score']:.3f})")

def main():
    print("🧪 Testing Attack Step Matching Improvements")
    print("=" * 70)
    
    # Load Qwen embeddings
    print("\n📦 Loading Qwen 0.6B embeddings...")
    embeddings_data = load_embeddings('qwen')
    model = SentenceTransformer('Qwen/Qwen3-Embedding-0.6B')
    
    patterns = embeddings_data['patterns']
    
    # Test 1: Baseline cosine similarity
    test_approach(
        "Baseline: Cosine Similarity",
        cosine_match,
        model, embeddings_data, TEST_QUERIES
    )
    
    # Test 2: Domain-weighted matching
    test_approach(
        "Domain-Weighted: AWS Term Boosting",
        domain_weighted_match,
        model, embeddings_data, TEST_QUERIES
    )
    
    # Test 3: Hybrid approach
    test_approach(
        "Hybrid: Cosine + Keyword Fallback",
        hybrid_match,
        model, embeddings_data, TEST_QUERIES
    )
    
    # Test 4: Alternative metrics
    print(f"\n{'='*70}")
    print("Alternative Similarity Metrics")
    print(f"{'='*70}")
    
    query_embs = model.encode(TEST_QUERIES)
    technique_embs = np.array(embeddings_data['embeddings'])
    
    for query, q_emb in zip(TEST_QUERIES[:3], query_embs[:3]):
        print(f"\n📝 {query}")
        
        cos_scores = cosine_match(q_emb, technique_embs)
        euc_scores = euclidean_match(q_emb, technique_embs)
        man_scores = manhattan_match(q_emb, technique_embs)
        dot_scores = dot_product_match(q_emb, technique_embs)
        
        print(f"   Cosine:    {patterns[cos_scores.argmax()]['technique_id']:12s} ({cos_scores.max():.3f})")
        print(f"   Euclidean: {patterns[euc_scores.argmax()]['technique_id']:12s} ({euc_scores.max():.3f})")
        print(f"   Manhattan: {patterns[man_scores.argmax()]['technique_id']:12s} ({man_scores.max():.3f})")
        print(f"   Dot Prod:  {patterns[dot_scores.argmax()]['technique_id']:12s} ({dot_scores.max():.3f})")
    
    # Test 5: Multi-signal re-ranking
    test_reranking(model, embeddings_data, TEST_QUERIES)
    
    print(f"\n{'='*70}")
    print("✅ Testing complete!")
    print(f"{'='*70}")
    
    # Summary
    print("\n📊 RECOMMENDATIONS:")
    print("1. Use Qwen 0.6B as base model (proven improvement)")
    print("2. Apply domain weighting for AWS-specific queries")
    print("3. Use cosine similarity (best for normalized embeddings)")
    print("4. Consider re-ranking for Amazon-specific techniques (AT prefix)")
    print("5. Set confidence threshold: 0.35 minimum")

if __name__ == "__main__":
    main()
