"""
Resource Enumeration CLI

Command-line interface for resource enumeration module.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import argparse
import asyncio
import json
import sys
import logging
from typing import List

from .schemas import ResourceEnumRequest, EnumMode
from .resource_orchestrator import ResourceOrchestrator


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_argparse() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Resource Enumeration - Discover endpoints with Katana, GAU, and Kiterunner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enumeration (Katana only)
  python -m app.recon.resource_enum.cli enumerate https://example.com --mode basic

  # Full enumeration (all tools)
  python -m app.recon.resource_enum.cli enumerate https://example.com --mode full -v

  # Passive enumeration (GAU only, historical data)
  python -m app.recon.resource_enum.cli enumerate example.com --mode passive

  # Active enumeration (Katana + Kiterunner)
  python -m app.recon.resource_enum.cli enumerate https://api.example.com --mode active

  # Enumerate from file
  python -m app.recon.resource_enum.cli enumerate -f targets.txt -o results.json

  # Custom configuration
  python -m app.recon.resource_enum.cli enumerate https://example.com \\
      --crawl-depth 5 --max-katana-urls 1000 --verify-urls -v
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Enumerate command
    enum_parser = subparsers.add_parser('enumerate', help='Enumerate resources')
    
    # Target specification
    target_group = enum_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        'targets',
        nargs='*',
        help='Target URLs or domains'
    )
    target_group.add_argument(
        '-f', '--file',
        type=str,
        help='File containing targets (one per line)'
    )
    
    # Mode selection
    enum_parser.add_argument(
        '--mode',
        type=str,
        choices=['basic', 'full', 'passive', 'active'],
        default='full',
        help='Enumeration mode (default: full)'
    )
    
    # Katana options
    katana_group = enum_parser.add_argument_group('Katana options')
    katana_group.add_argument(
        '--no-katana',
        action='store_true',
        help='Disable Katana crawling'
    )
    katana_group.add_argument(
        '--crawl-depth',
        type=int,
        default=3,
        help='Maximum crawl depth (1-5, default: 3)'
    )
    katana_group.add_argument(
        '--max-katana-urls',
        type=int,
        default=500,
        help='Maximum URLs to crawl (default: 500)'
    )
    katana_group.add_argument(
        '--no-js',
        action='store_true',
        help='Disable JavaScript rendering'
    )
    katana_group.add_argument(
        '--no-forms',
        action='store_true',
        help='Disable form extraction'
    )
    
    # GAU options
    gau_group = enum_parser.add_argument_group('GAU options')
    gau_group.add_argument(
        '--no-gau',
        action='store_true',
        help='Disable GAU'
    )
    gau_group.add_argument(
        '--gau-providers',
        nargs='+',
        choices=['wayback', 'commoncrawl', 'otx', 'urlscan'],
        default=['wayback', 'commoncrawl', 'otx', 'urlscan'],
        help='GAU providers to use'
    )
    gau_group.add_argument(
        '--max-gau-urls',
        type=int,
        default=1000,
        help='Maximum historical URLs (default: 1000)'
    )
    gau_group.add_argument(
        '--no-verify',
        action='store_true',
        help='Disable URL liveness verification'
    )
    
    # Kiterunner options
    kite_group = enum_parser.add_argument_group('Kiterunner options')
    kite_group.add_argument(
        '--no-kiterunner',
        action='store_true',
        help='Disable Kiterunner'
    )
    kite_group.add_argument(
        '--wordlist',
        type=str,
        default='routes-large',
        help='Wordlist to use (default: routes-large)'
    )
    kite_group.add_argument(
        '--kite-threads',
        type=int,
        default=10,
        help='Number of Kiterunner threads (default: 10)'
    )
    kite_group.add_argument(
        '--kite-rate-limit',
        type=int,
        default=100,
        help='Kiterunner rate limit (req/s, default: 100)'
    )
    
    # General options
    enum_parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Overall timeout in seconds (default: 300)'
    )
    enum_parser.add_argument(
        '--sequential',
        action='store_true',
        help='Run tools sequentially instead of in parallel'
    )
    enum_parser.add_argument(
        '--no-classify',
        action='store_true',
        help='Disable endpoint classification'
    )
    enum_parser.add_argument(
        '--no-infer-types',
        action='store_true',
        help='Disable parameter type inference'
    )
    
    # Output options
    enum_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output JSON file'
    )
    enum_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    return parser


def load_targets_from_file(filepath: str) -> List[str]:
    """Load targets from a file."""
    try:
        with open(filepath, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return targets
    except Exception as e:
        logger.error(f"Error loading targets from file: {e}")
        sys.exit(1)


async def enumerate_command(args: argparse.Namespace) -> None:
    """Execute enumerate command."""
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get targets
    if args.file:
        targets = load_targets_from_file(args.file)
    else:
        targets = args.targets
    
    if not targets:
        logger.error("No targets specified")
        sys.exit(1)
    
    logger.info(f"Enumerating {len(targets)} target(s) in {args.mode} mode")
    
    # Build request
    request = ResourceEnumRequest(
        targets=targets,
        mode=EnumMode(args.mode),
        katana_enabled=not args.no_katana,
        crawl_depth=args.crawl_depth,
        max_katana_urls=args.max_katana_urls,
        js_crawling=not args.no_js,
        extract_forms=not args.no_forms,
        gau_enabled=not args.no_gau,
        gau_providers=args.gau_providers,
        max_gau_urls=args.max_gau_urls,
        verify_urls=not args.no_verify,
        kiterunner_enabled=not args.no_kiterunner,
        wordlist=args.wordlist,
        kite_threads=args.kite_threads,
        kite_rate_limit=args.kite_rate_limit,
        timeout=args.timeout,
        parallel_execution=not args.sequential,
        classify_endpoints=not args.no_classify,
        infer_param_types=not args.no_infer_types
    )
    
    # Run enumeration
    orchestrator = ResourceOrchestrator(request)
    result = await orchestrator.run()
    
    # Display results
    print("\n" + "="*80)
    print("RESOURCE ENUMERATION RESULTS")
    print("="*80)
    
    print("\n📊 Statistics:")
    print(f"  Total Endpoints: {result.stats.total_endpoints}")
    print(f"  Katana: {result.stats.katana_endpoints}")
    print(f"  GAU: {result.stats.gau_endpoints}")
    print(f"  Kiterunner: {result.stats.kiterunner_endpoints}")
    print(f"  Live Endpoints: {result.stats.live_endpoints}")
    print(f"  Total Parameters: {result.stats.total_parameters}")
    print(f"  Total Forms: {result.stats.total_forms}")
    print(f"  Execution Time: {result.stats.execution_time}s")
    
    if result.stats.categories:
        print("\n📂 Categories:")
        for category, count in sorted(result.stats.categories.items(), key=lambda x: -x[1]):
            print(f"  {category}: {count}")
    
    if result.stats.methods:
        print("\n🔧 HTTP Methods:")
        for method, count in sorted(result.stats.methods.items(), key=lambda x: -x[1]):
            print(f"  {method}: {count}")
    
    if result.errors:
        print(f"\n⚠️  Errors ({len(result.errors)}):")
        for error in result.errors[:5]:
            print(f"  - {error}")
        if len(result.errors) > 5:
            print(f"  ... and {len(result.errors) - 5} more")
    
    # Display sample endpoints
    if result.endpoints:
        print("\n🔍 Sample Endpoints (showing first 10):")
        for i, endpoint in enumerate(result.endpoints[:10], 1):
            print(f"\n  {i}. {endpoint.method} {endpoint.url}")
            print(f"     Source: {endpoint.source} | Category: {endpoint.category.value}")
            if endpoint.status_code:
                print(f"     Status: {endpoint.status_code}")
            if endpoint.parameters:
                print(f"     Parameters: {', '.join([f'{p.name}({p.type.value})' for p in endpoint.parameters[:5]])}")
            if endpoint.forms:
                print(f"     Forms: {len(endpoint.forms)}")
    
    # Save to file if requested
    if args.output:
        try:
            output_data = result.model_dump(mode='json')
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\n💾 Results saved to: {args.output}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    print("\n" + "="*80)
    print(f"✅ Enumeration complete: {result.stats.total_endpoints} endpoints discovered")
    print("="*80 + "\n")


def main():
    """Main entry point."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'enumerate':
        asyncio.run(enumerate_command(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
