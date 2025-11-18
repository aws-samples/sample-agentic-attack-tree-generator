#!/usr/bin/env python3
import json
import numpy as np
from sentence_transformers import SentenceTransformer

def create_embeddings():
    # Load STIX bundle
    with open('../stix-data/aaf-bundle.json', 'r') as f:
        bundle = json.load(f)
    
    # Load model
    model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')
    
    # Extract attack patterns
    patterns = []
    texts = []
    
    for obj in bundle['objects']:
        if obj['type'] == 'attack-pattern':
            # Combine name + description for richer context
            text = f"{obj['name']}: {obj['description']}"
            texts.append(text)
            
            patterns.append({
                'id': obj['id'],
                'name': obj['name'],
                'description': obj['description'],
                'technique_id': obj.get('aliases', [None])[0],
                'kill_chain_phases': obj.get('kill_chain_phases', [])
            })
    
    print(f"Creating embeddings for {len(patterns)} attack patterns...")
    
    # Generate embeddings
    embeddings = model.encode(texts, show_progress_bar=True)
    
    # Save results
    output = {
        'patterns': patterns,
        'embeddings': embeddings.tolist(),
        'model': 'sentence-transformers/all-mpnet-base-v2',
        'embedding_dim': embeddings.shape[1]
    }
    
    with open('attack_pattern_embeddings.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"✅ Saved {len(patterns)} embeddings to attack_pattern_embeddings.json")
    print(f"Embedding dimensions: {embeddings.shape[1]}")

if __name__ == "__main__":
    create_embeddings()
