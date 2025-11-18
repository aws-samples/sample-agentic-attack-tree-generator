#!/usr/bin/env python3
import argparse
import json
import numpy as np
import glob
import re
import os
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

def create_embeddings():
    """Generate embeddings from STIX attack patterns"""
    print("Loading STIX bundle...")
    with open('../stix-data/aaf-bundle.json', 'r') as f:
        bundle = json.load(f)
    
    model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')
    
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
                'technique_id': obj.get('aliases', [None])[0],
                'kill_chain_phases': obj.get('kill_chain_phases', [])
            })
    
    print(f"Creating embeddings for {len(patterns)} techniques...")
    embeddings = model.encode(texts, show_progress_bar=True)
    
    output = {
        'patterns': patterns,
        'embeddings': embeddings.tolist(),
        'model': 'sentence-transformers/all-mpnet-base-v2',
        'embedding_dim': embeddings.shape[1]
    }
    
    with open('attack_pattern_embeddings.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"✅ Saved {len(patterns)} embeddings")

def extract_attack_steps(file_path):
    """Extract attack steps from mermaid diagram"""
    with open(file_path, 'r') as f:
        content = f.read()
    
    mermaid_match = re.search(r'```mermaid\n(.*?)\n```', content, re.DOTALL)
    if not mermaid_match:
        return []
    
    steps = []
    for line in mermaid_match.group(1).split('\n'):
        matches = re.findall(r'\["([^"]+)"\]', line)
        steps.extend(matches)
    
    return list(set(steps))

def get_attack_tree_files(input_path=None):
    """Get list of attack tree files from input path or default location"""
    if input_path:
        if os.path.isfile(input_path):
            # Single file
            return [input_path]
        elif os.path.isdir(input_path):
            # Directory - find all .md files
            return glob.glob(os.path.join(input_path, '*.md'))
        else:
            print(f"❌ Path not found: {input_path}")
            return []
    else:
        # Default location
        return glob.glob('../output/attack_tree_*.md')

def match_steps(input_path=None):
    """Match attack steps to techniques"""
    with open('attack_pattern_embeddings.json', 'r') as f:
        embeddings_data = json.load(f)
    
    model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')
    technique_embeddings = np.array(embeddings_data['embeddings'])
    patterns = embeddings_data['patterns']
    
    attack_tree_files = get_attack_tree_files(input_path)
    if not attack_tree_files:
        print("❌ No attack tree files found")
        return
        
    all_results = {}
    
    for file_path in attack_tree_files:
        print(f"Processing {os.path.basename(file_path)}...")
        
        steps = extract_attack_steps(file_path)
        if not steps:
            continue
            
        step_embeddings = model.encode(steps)
        similarities = cosine_similarity(step_embeddings, technique_embeddings)
        
        results = []
        for i, step in enumerate(steps):
            top_indices = similarities[i].argsort()[-3:][::-1]
            
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
        
        file_name = os.path.basename(file_path)
        all_results[file_name] = results
    
    with open('attack_step_matches.json', 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"✅ Processed {len(all_results)} attack trees")

def show_matches(file_filter=None, min_similarity=0.3, top_n=1):
    """Show technique matches"""
    with open('attack_step_matches.json', 'r') as f:
        matches = json.load(f)
    
    for filename, file_matches in matches.items():
        if file_filter and file_filter not in filename:
            continue
            
        print(f"\n📋 {filename}:")
        
        for match in file_matches:
            good_matches = [m for m in match['matches'][:top_n] if m['similarity'] >= min_similarity]
            if good_matches:
                print(f"  {match['attack_step']}")
                for m in good_matches:
                    print(f"    → {m['technique_id']} - {m['name']} ({m['similarity']:.3f})")

def list_techniques(search=None):
    """List available techniques"""
    with open('attack_pattern_embeddings.json', 'r') as f:
        data = json.load(f)
    
    patterns = data['patterns']
    
    if search:
        patterns = [p for p in patterns if search.lower() in p['name'].lower() or 
                   search.lower() in p['description'].lower()]
    
    print(f"Found {len(patterns)} techniques:")
    for p in patterns[:20]:  # Limit output
        tid = p.get('technique_id', 'N/A')
        print(f"  {tid} - {p['name']}")
    
    if len(patterns) > 20:
        print(f"  ... and {len(patterns) - 20} more")

def find_technique(query, top_k=5):
    """Find techniques similar to query"""
    with open('attack_pattern_embeddings.json', 'r') as f:
        data = json.load(f)
    
    model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2')
    
    query_embedding = model.encode([query])
    technique_embeddings = np.array(data['embeddings'])
    
    similarities = cosine_similarity(query_embedding, technique_embeddings)[0]
    top_indices = similarities.argsort()[-top_k:][::-1]
    
    print(f"Top {top_k} techniques for: '{query}'")
    for idx in top_indices:
        pattern = data['patterns'][idx]
        tid = pattern.get('technique_id', 'N/A')
        print(f"  {tid} - {pattern['name']} ({similarities[idx]:.3f})")

def enrich_attack_trees(min_similarity=0.3, output_dir='../output/enriched', input_path=None):
    """Enrich attack tree files with technique data"""
    import os
    
    # Load matches and embeddings
    with open('attack_step_matches.json', 'r') as f:
        matches = json.load(f)
    
    with open('attack_pattern_embeddings.json', 'r') as f:
        embed_data = json.load(f)
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Get files to process
    attack_tree_files = get_attack_tree_files(input_path)
    if not attack_tree_files:
        print("❌ No attack tree files found")
        return
    
    processed = 0
    for file_path in attack_tree_files:
        file_name = os.path.basename(file_path)
        
        # Check if we have matches for this file
        if file_name not in matches:
            print(f"⚠️  No matches found for {file_name}, skipping...")
            continue
            
        file_matches = matches[file_name]
        output_path = os.path.join(output_dir, file_name)
        
        print(f"Enriching {file_name}...")
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Find mermaid diagram
        mermaid_match = re.search(r'(```mermaid\n)(.*?)(\n```)', content, re.DOTALL)
        if not mermaid_match:
            print(f"⚠️  No mermaid diagram found in {file_name}")
            continue
        
        mermaid_start = mermaid_match.group(1)
        mermaid_content = mermaid_match.group(2)
        mermaid_end = mermaid_match.group(3)
        
        # Build step-to-technique mapping
        step_techniques = {}
        enrichments = []
        
        for match in file_matches:
            best_match = match['matches'][0]
            if best_match['similarity'] >= min_similarity:
                step = match['attack_step']
                technique_id = best_match['technique_id'] or 'N/A'
                name = best_match['name']
                
                # Get kill chain phases
                kill_chains = []
                for pattern in embed_data['patterns']:
                    if pattern['name'] == name:
                        for phase in pattern.get('kill_chain_phases', []):
                            kill_chains.append(phase.get('phase_name', ''))
                        break
                
                kill_chain_str = ', '.join(kill_chains) if kill_chains else 'N/A'
                
                step_techniques[step] = {
                    'technique_id': technique_id,
                    'name': name,
                    'kill_chain': kill_chain_str,
                    'similarity': best_match['similarity']
                }
                
                enrichments.append({
                    'step': step,
                    'technique_id': technique_id,
                    'name': name,
                    'kill_chain': kill_chain_str,
                    'similarity': best_match['similarity']
                })
        
        # Update mermaid diagram
        updated_mermaid = mermaid_content
        for step, tech_data in step_techniques.items():
            # Find the step in mermaid and add technique info
            pattern = rf'(\["?)({re.escape(step)})(\]?")'
            
            # Create enriched step text
            enriched_step = f"{step}<br/><small>{tech_data['technique_id']}</small>"
            replacement = rf'\1{enriched_step}\3'
            
            updated_mermaid = re.sub(pattern, replacement, updated_mermaid)
        
        # Replace mermaid diagram in content
        updated_content = content.replace(
            mermaid_start + mermaid_content + mermaid_end,
            mermaid_start + updated_mermaid + mermaid_end
        )
        
        # Add enrichment table
        enrichment_section = "\n\n---\n\n## 🎯 Technique Mappings\n\n"
        enrichment_section += "| Attack Step | Technique ID | Technique Name | Kill Chain Phase | Confidence |\n"
        enrichment_section += "|-------------|--------------|----------------|------------------|------------|\n"
        
        for enrich in enrichments:
            enrichment_section += f"| {enrich['step'][:50]}{'...' if len(enrich['step']) > 50 else ''} | "
            enrichment_section += f"{enrich['technique_id']} | {enrich['name'][:30]}{'...' if len(enrich['name']) > 30 else ''} | "
            enrichment_section += f"{enrich['kill_chain']} | {enrich['similarity']:.3f} |\n"
        
        # Write enriched file
        final_content = updated_content + enrichment_section
        with open(output_path, 'w') as f:
            f.write(final_content)
        
        processed += 1
    
    print(f"✅ Enriched {processed} files saved to {output_dir}/")
    print(f"Updated mermaid diagrams and added technique mappings with similarity >= {min_similarity}")

def main():
    parser = argparse.ArgumentParser(description='ThreatForest Embedding CLI')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create embeddings
    subparsers.add_parser('create', help='Create embeddings from STIX data')
    
    # Match attack steps
    match_parser = subparsers.add_parser('match', help='Match attack steps to techniques')
    match_parser.add_argument('--input', help='Input file or directory (default: ../output/attack_tree_*.md)')
    
    # Show matches
    show_parser = subparsers.add_parser('show', help='Show technique matches')
    show_parser.add_argument('--file', help='Filter by filename')
    show_parser.add_argument('--min-similarity', type=float, default=0.3, help='Minimum similarity')
    show_parser.add_argument('--top', type=int, default=1, help='Top N matches per step')
    
    # List techniques
    list_parser = subparsers.add_parser('list', help='List available techniques')
    list_parser.add_argument('--search', help='Search techniques')
    
    # Find technique
    find_parser = subparsers.add_parser('find', help='Find techniques similar to query')
    find_parser.add_argument('query', help='Search query')
    find_parser.add_argument('--top', type=int, default=5, help='Top N results')
    
    # Enrich attack trees
    enrich_parser = subparsers.add_parser('enrich', help='Enrich attack trees with technique data')
    enrich_parser.add_argument('--input', help='Input file or directory (default: ../output/attack_tree_*.md)')
    enrich_parser.add_argument('--min-similarity', type=float, default=0.3, help='Minimum similarity')
    enrich_parser.add_argument('--output-dir', default='../output/enriched', help='Output directory')
    
    args = parser.parse_args()
    
    if args.command == 'create':
        create_embeddings()
    elif args.command == 'match':
        match_steps(getattr(args, 'input', None))
    elif args.command == 'show':
        show_matches(args.file, args.min_similarity, args.top)
    elif args.command == 'list':
        list_techniques(args.search)
    elif args.command == 'find':
        find_technique(args.query, args.top)
    elif args.command == 'enrich':
        enrich_attack_trees(args.min_similarity, args.output_dir, getattr(args, 'input', None))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
