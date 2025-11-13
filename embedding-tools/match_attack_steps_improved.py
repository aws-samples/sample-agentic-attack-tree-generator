#!/usr/bin/env python3
"""Improved attack step matching with domain weighting and Qwen 0.6B"""
import json
import numpy as np
import re
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import glob

AWS_TERMS = ['aws', 's3', 'ec2', 'iam', 'lambda', 'dynamodb', 'rds', 'ecs', 
             'cloudformation', 'cloudwatch', 'sns', 'sqs', 'kinesis', 'athena',
             'glue', 'emr', 'eks', 'fargate', 'bucket', 'instance', 'role',
             'cloudtrail', 'kms', 'secrets', 'parameter', 'api', 'gateway']

def extract_attack_steps_from_md(file_path):
    """Extract attack steps from mermaid diagram in markdown file"""
    with open(file_path, 'r') as f:
        content = f.read()
    
    mermaid_match = re.search(r'```mermaid\n(.*?)\n```', content, re.DOTALL)
    if not mermaid_match:
        return []
    
    mermaid_content = mermaid_match.group(1)
    steps = []
    for line in mermaid_content.split('\n'):
        matches = re.findall(r'\["([^"]+)"\]', line)
        steps.extend(matches)
    
    return list(set(steps))

def match_with_domain_weighting(attack_steps, embeddings_data, model, top_k=3, min_similarity=0.0):
    """Match attack steps using cosine similarity with AWS term boosting"""
    
    technique_embs = np.array(embeddings_data['embeddings'])
    patterns = embeddings_data['patterns']
    
    # Generate embeddings for attack steps
    step_embeddings = model.encode(attack_steps)
    
    # Calculate base similarities
    base_similarities = cosine_similarity(step_embeddings, technique_embs)
    
    results = []
    for i, step in enumerate(attack_steps):
        step_lower = step.lower()
        weighted_scores = []
        
        # Apply domain weighting
        for j, pattern in enumerate(patterns):
            tech_text = f"{pattern['name']} {pattern['description']}".lower()
            boost = 1.0
            
            # Boost for matching AWS terms
            for term in AWS_TERMS:
                if term in step_lower and term in tech_text:
                    boost += 0.1
            
            weighted_scores.append(base_similarities[i][j] * min(boost, 1.5))
        
        # Get top-k matches above threshold
        top_indices = np.argsort(weighted_scores)[-top_k:][::-1]
        
        matches = []
        for idx in top_indices:
            similarity = weighted_scores[idx]
            if similarity >= min_similarity:
                matches.append({
                    'technique_id': patterns[idx].get('technique_id'),
                    'name': patterns[idx]['name'],
                    'description': patterns[idx]['description'][:100] + '...',
                    'similarity': float(similarity),
                    'confidence': 'high' if similarity > 0.7 else 'medium' if similarity > 0.5 else 'low'
                })
        
        if matches:
            results.append({
                'attack_step': step,
                'matches': matches
            })
    
    return results

def main():
    # Load embeddings (Qwen 0.6B)
    print("📦 Loading Qwen 0.6B embeddings...")
    with open('attack_pattern_embeddings_qwen.json', 'r') as f:
        embeddings_data = json.load(f)
    
    # Load model
    model = SentenceTransformer('Qwen/Qwen3-Embedding-0.6B')
    
    # Process all attack tree files
    attack_tree_files = glob.glob('../output/attack_tree_*.md')
    
    all_results = {}
    
    for file_path in attack_tree_files:
        print(f"Processing {file_path}...")
        
        steps = extract_attack_steps_from_md(file_path)
        if not steps:
            continue
            
        # Match with domain weighting
        matches = match_with_domain_weighting(steps, embeddings_data, model, top_k=3, min_similarity=0.3)
        
        file_name = file_path.split('/')[-1]
        all_results[file_name] = matches
    
    # Save results
    with open('attack_step_matches_improved.json', 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"✅ Saved improved matches to attack_step_matches_improved.json")
    
    # Print sample with confidence levels
    for file_name, matches in list(all_results.items())[:1]:
        print(f"\n📋 Sample from {file_name}:")
        for match in matches[:3]:
            step = match['attack_step']
            best = match['matches'][0]
            confidence_emoji = '🟢' if best['confidence'] == 'high' else '🟡' if best['confidence'] == 'medium' else '🔴'
            print(f"  {confidence_emoji} {step}")
            print(f"     → {best['technique_id']} - {best['name']}")
            print(f"     Similarity: {best['similarity']:.3f} ({best['confidence']})")

if __name__ == "__main__":
    main()
