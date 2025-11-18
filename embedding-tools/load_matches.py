#!/usr/bin/env python3
import json

def load_matches():
    """Load attack step matches from JSON file"""
    with open('attack_step_matches.json', 'r') as f:
        return json.load(f)

def get_matches_for_file(matches, filename, min_similarity=0.3):
    """Get matches for specific attack tree file with similarity threshold"""
    if filename not in matches:
        return []
    
    filtered_matches = []
    for match in matches[filename]:
        # Filter by similarity threshold
        good_matches = [m for m in match['matches'] if m['similarity'] >= min_similarity]
        if good_matches:
            filtered_matches.append({
                'attack_step': match['attack_step'],
                'matches': good_matches
            })
    
    return filtered_matches

def print_matches(matches, filename):
    """Print matches for a specific file"""
    file_matches = get_matches_for_file(matches, filename)
    
    print(f"\n📋 {filename}:")
    for match in file_matches:
        step = match['attack_step']
        best = match['matches'][0]
        print(f"  {step}")
        print(f"  → {best['technique_id']} - {best['name']} ({best['similarity']:.3f})")

if __name__ == "__main__":
    # Load matches
    matches = load_matches()
    
    # Example usage
    for filename in list(matches.keys())[:3]:
        print_matches(matches, filename)
