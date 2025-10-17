#!/usr/bin/env python3
import json
import numpy as np
import re
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import glob

def extract_attack_steps_from_md(file_path):
    """Extract attack steps from mermaid diagram in markdown file"""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract mermaid diagram
    mermaid_match = re.search(r'```mermaid\n(.*?)\n```', content, re.DOTALL)
    if not mermaid_match:
        return []
    
    mermaid_content = mermaid_match.group(1)
    
    # Extract step descriptions from mermaid nodes
    steps = []
    for line in mermaid_content.split('\n'):
        # Match patterns like: A["Step description"] or --> B["Step description"]
        matches = re.findall(r'\["([^"]+)"\]', line)
        steps.extend(matches)
    
    return list(set(steps))  # Remove duplicates

def match_steps_to_techniques(attack_steps, embeddings_data, model, top_k=3):
    """Match attack steps to STIX techniques using embeddings"""
    
    # Load embeddings
    technique_embeddings = np.array(embeddings_data['embeddings'])
    patterns = embeddings_data['patterns']
    
    # Generate embeddings for attack steps
    step_embeddings = model.encode(attack_steps)
    
    # Calculate similarities
    similarities = cosine_similarity(step_embeddings, technique_embeddings)
    
    results = []
    for i, step in enumerate(attack_steps):
        # Get top-k most similar techniques
        top_indices = similarities[i].argsort()[-top_k:][::-1]
        
        matches = []
        for idx in top_indices:
            matches.append({
                'technique_id': patterns[idx].get('technique_id'),
                'name': patterns[idx]['name'],
                'description': patterns[idx]['description'][:100] + '...',
                'similarity': float(similarities[i][idx])
            })
        
        results.append({
            'attack_step': step,
            'matches': matches
        })
    
    return results

def main():
    # Load embeddings
    with open('attack_pattern_embeddings.json', 'r') as f:
        embeddings_data = json.load(f)
    
    # Load model
    model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')
    
    # Process all attack tree files
    attack_tree_files = glob.glob('../output/attack_tree_*.md')
    
    all_results = {}
    
    for file_path in attack_tree_files:
        print(f"Processing {file_path}...")
        
        # Extract attack steps
        steps = extract_attack_steps_from_md(file_path)
        if not steps:
            continue
            
        # Match to techniques
        matches = match_steps_to_techniques(steps, embeddings_data, model)
        
        file_name = file_path.split('/')[-1]
        all_results[file_name] = matches
    
    # Save results
    with open('attack_step_matches.json', 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"✅ Saved attack step matches to attack_step_matches.json")
    
    # Print sample results
    for file_name, matches in list(all_results.items())[:1]:
        print(f"\n📋 Sample from {file_name}:")
        for match in matches[:2]:
            print(f"  Step: {match['attack_step']}")
            print(f"  Best match: {match['matches'][0]['technique_id']} - {match['matches'][0]['name']}")
            print(f"  Similarity: {match['matches'][0]['similarity']:.3f}")

if __name__ == "__main__":
    main()
