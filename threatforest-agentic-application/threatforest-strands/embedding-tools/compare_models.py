#!/usr/bin/env python3
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import time

MODELS = {
    'mpnet': 'sentence-transformers/all-mpnet-base-v2',
    'qwen': 'Qwen/Qwen3-Embedding-0.6B',
    'qwen4b': 'Qwen/Qwen3-Embedding-4B'
}

def create_embeddings_for_model(model_name, model_id):
    """Create embeddings using specified model"""
    print(f"\n{'='*60}")
    print(f"Processing model: {model_name} ({model_id})")
    print(f"{'='*60}")
    
    # Load STIX bundle
    with open('../stix-data/aaf-bundle.json', 'r') as f:
        bundle = json.load(f)
    
    # Load model
    start_time = time.time()
    model = SentenceTransformer(model_id)
    load_time = time.time() - start_time
    print(f"⏱️  Model loaded in {load_time:.2f}s")
    
    # Extract attack patterns
    patterns = []
    texts = []
    
    for obj in bundle['objects']:
        if obj['type'] == 'attack-pattern':
            text = f"{obj['name']}: {obj['description']}"
            texts.append(text)
            patterns.append({
                'id': obj['id'],
                'name': obj['name'],
                'description': obj['description'],
                'technique_id': obj.get('aliases', [None])[0]
            })
    
    # Generate embeddings with smaller batch size for large models
    batch_size = 8 if '4B' in model_id else 32
    start_time = time.time()
    embeddings = model.encode(texts, show_progress_bar=True, batch_size=batch_size)
    encode_time = time.time() - start_time
    
    print(f"⏱️  Encoded {len(patterns)} patterns in {encode_time:.2f}s")
    print(f"📊 Embedding dimensions: {embeddings.shape[1]}")
    
    # Save results
    output = {
        'patterns': patterns,
        'embeddings': embeddings.tolist(),
        'model': model_id,
        'embedding_dim': embeddings.shape[1],
        'load_time': load_time,
        'encode_time': encode_time
    }
    
    output_file = f'attack_pattern_embeddings_{model_name}.json'
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"✅ Saved to {output_file}")
    
    return output, model

def compare_matching_quality(sample_queries):
    """Compare how different models match sample queries"""
    print(f"\n{'='*60}")
    print("MATCHING QUALITY COMPARISON")
    print(f"{'='*60}")
    
    results = {}
    
    for model_name, model_id in MODELS.items():
        print(f"\n🔍 Testing {model_name}...")
        
        # Load embeddings
        with open(f'attack_pattern_embeddings_{model_name}.json', 'r') as f:
            data = json.load(f)
        
        model = SentenceTransformer(model_id)
        technique_embeddings = np.array(data['embeddings'])
        patterns = data['patterns']
        
        # Encode queries
        query_embeddings = model.encode(sample_queries)
        similarities = cosine_similarity(query_embeddings, technique_embeddings)
        
        model_results = []
        for i, query in enumerate(sample_queries):
            top_idx = similarities[i].argmax()
            model_results.append({
                'query': query,
                'match': patterns[top_idx]['name'],
                'technique_id': patterns[top_idx]['technique_id'],
                'similarity': float(similarities[i][top_idx])
            })
        
        results[model_name] = model_results
    
    # Print comparison
    for i, query in enumerate(sample_queries):
        print(f"\n📝 Query: {query}")
        for model_name in MODELS.keys():
            r = results[model_name][i]
            print(f"  {model_name:8s}: {r['technique_id']:12s} {r['match']:40s} ({r['similarity']:.3f})")
    
    return results

def main():
    # Create embeddings for all models
    for model_name, model_id in MODELS.items():
        output_file = f'attack_pattern_embeddings_{model_name}.json'
        try:
            with open(output_file, 'r') as f:
                json.load(f)
            print(f"⏭️  Skipping {model_name} - embeddings already exist")
        except FileNotFoundError:
            create_embeddings_for_model(model_name, model_id)
    
    # Compare matching quality with sample queries
    sample_queries = [
        "Steal credentials from memory",
        "Execute malicious code remotely",
        "Escalate privileges using vulnerability",
        "Exfiltrate data over encrypted channel"
    ]
    
    compare_matching_quality(sample_queries)
    
    print(f"\n{'='*60}")
    print("✅ Comparison complete!")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
