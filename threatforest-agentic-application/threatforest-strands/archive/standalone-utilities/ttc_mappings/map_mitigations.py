#!/usr/bin/env python3
"""CLI tool to map mitigations to enriched attack trees"""
import sys
from pathlib import Path
from mitigation_mapper import MitigationMapper


def main():
    # Load config
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from config import config
    
    # Default paths from config
    bundle_path = config.stix_bundle_path
    enriched_dir = Path(__file__).parent.parent.parent.parent / "output" / "enriched_v2"
    output_dir = Path(__file__).parent.parent.parent.parent / "output" / "mitigated"
    
    # Allow overrides
    if len(sys.argv) > 1:
        enriched_dir = Path(sys.argv[1])
    if len(sys.argv) > 2:
        output_dir = Path(sys.argv[2])
    if len(sys.argv) > 3:
        bundle_path = Path(sys.argv[3])
    
    print(f"📦 Bundle: {bundle_path}")
    print(f"📂 Input: {enriched_dir}")
    print(f"📁 Output: {output_dir}\n")
    
    mapper = MitigationMapper(str(bundle_path))
    
    files = list(enriched_dir.glob('*.md'))
    output_dir.mkdir(exist_ok=True, parents=True)
    
    for file_path in files:
        output_path = output_dir / f"mitigated_{file_path.name}"
        result = mapper.process_enriched_file(str(file_path), str(output_path))
        
        status = "✅" if result['mitigations_found'] else "⚪"
        print(f"{status} {file_path.name}: {len(result['techniques'])} techniques")
    
    print(f"\n✓ Processed {len(files)} files → {output_dir}")


if __name__ == '__main__':
    main()
