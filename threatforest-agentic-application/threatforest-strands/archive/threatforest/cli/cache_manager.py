"""CLI utility for managing Bedrock response cache"""
import argparse
from pathlib import Path
from threatforest.core.cache import BedrockResponseCache


def main():
    """Main entry point for cache management CLI"""
    parser = argparse.ArgumentParser(
        description="Manage ThreatForest Bedrock response cache"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Cache management commands')
    
    # Stats command
    subparsers.add_parser('stats', help='Show cache statistics')
    
    # Clear command
    subparsers.add_parser('clear', help='Clear all cached responses')
    
    # Info command
    subparsers.add_parser('info', help='Show cache configuration and location')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cache = BedrockResponseCache()
    
    if args.command == 'stats':
        stats = cache.get_stats()
        print("\n📊 Cache Statistics")
        print("=" * 50)
        print(f"Total Entries: {stats['entry_count']}")
        print(f"Cache Hits: {stats['hits']}")
        print(f"Cache Misses: {stats['misses']}")
        print(f"Hit Rate: {stats['hit_rate']}")
        print(f"Total Size: {stats['cache_size_mb']} MB")
        print(f"Size Limit: {cache.MAX_CACHE_SIZE_MB} MB")
        print()
    
    elif args.command == 'clear':
        cache.clear()
        print("✅ Cache cleared successfully")
    
    elif args.command == 'info':
        print("\n📁 Cache Configuration")
        print("=" * 50)
        print(f"Cache Directory: {cache.cache_dir}")
        print(f"Default TTL: {cache.DEFAULT_TTL / 3600:.0f} hours")
        print(f"Max Size: {cache.MAX_CACHE_SIZE_MB} MB")
        print(f"Enabled: {'Yes' if cache.enabled else 'No'}")
        print()


if __name__ == '__main__':
    main()
