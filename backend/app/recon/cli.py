#!/usr/bin/env python
"""
Command-Line Interface for UniVex Reconnaissance Module

Usage:
    python -m app.recon.cli discover example.com
    python -m app.recon.cli discover example.com --output results.json
    python -m app.recon.cli discover example.com --verbose
"""

import asyncio
import argparse
import sys
import logging
from typing import Optional

from app.recon.domain_discovery import DomainDiscovery


def setup_logging(verbose: bool = False):
    """
    Configure logging for CLI.

    Args:
        verbose: Enable verbose (DEBUG) logging
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


async def run_discovery(
    domain: str,
    output: Optional[str] = None,
    hackertarget_api_key: Optional[str] = None,
    dns_nameservers: Optional[list] = None,
    verbose: bool = False
):
    """
    Run domain discovery and optionally save results.

    Args:
        domain: Target domain
        output: Optional output file path
        hackertarget_api_key: Optional HackerTarget API key
        dns_nameservers: Optional list of DNS nameservers
        verbose: Enable verbose output
    """
    setup_logging(verbose)
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"Starting reconnaissance for {domain}")
        
        # Initialize discovery
        discovery = DomainDiscovery(
            domain=domain,
            hackertarget_api_key=hackertarget_api_key,
            dns_nameservers=dns_nameservers
        )
        
        # Run discovery
        results = await discovery.run()
        
        # Print summary
        print("\n" + "="*60)
        print(f"Domain Discovery Results for {domain}")
        print("="*60)
        
        summary = discovery.get_summary()
        print(f"\nDuration: {summary['duration']:.2f} seconds")
        print(f"WHOIS Available: {summary['whois_available']}")
        
        if summary.get('statistics'):
            stats = summary['statistics']
            print(f"\nSubdomains Found: {stats.get('total_subdomains', 0)}")
            print(f"Resolved Subdomains: {stats.get('resolved_subdomains', 0)}")
            print(f"Unique IPs: {stats.get('total_ips', 0)}")
            print(f"  - IPv4: {stats.get('ipv4_count', 0)}")
            print(f"  - IPv6: {stats.get('ipv6_count', 0)}")
            
            if stats.get('record_types'):
                print("\nDNS Record Types Found:")
                for record_type, count in stats['record_types'].items():
                    print(f"  - {record_type}: {count}")
        
        # Print subdomains
        if results.get('subdomains'):
            print(f"\n Found {len(results['subdomains'])} Subdomains:")
            for subdomain in results['subdomains'][:20]:  # Show first 20
                print(f"  - {subdomain}")
            if len(results['subdomains']) > 20:
                print(f"  ... and {len(results['subdomains']) - 20} more")
        
        # Save to file if requested
        if output:
            discovery.export_json(output)
            print(f"\n✓ Results saved to {output}")
        
        print("\n" + "="*60)
        print("Discovery Complete!")
        print("="*60 + "\n")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during discovery: {str(e)}", exc_info=True)
        print(f"\n✗ Error: {str(e)}\n", file=sys.stderr)
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="UniVex Reconnaissance CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s discover example.com
  %(prog)s discover example.com --output results.json
  %(prog)s discover example.com --verbose
  %(prog)s discover example.com --api-key YOUR_KEY --dns 8.8.8.8,8.8.4.4
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Discover command
    discover_parser = subparsers.add_parser(
        'discover',
        help='Perform domain discovery and reconnaissance'
    )
    discover_parser.add_argument(
        'domain',
        type=str,
        help='Target domain to investigate'
    )
    discover_parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Output file path for JSON results'
    )
    discover_parser.add_argument(
        '-k', '--api-key',
        type=str,
        default=None,
        help='HackerTarget API key (optional, for increased rate limits)'
    )
    discover_parser.add_argument(
        '-d', '--dns',
        type=str,
        default=None,
        help='Custom DNS nameservers (comma-separated, e.g., 8.8.8.8,8.8.4.4)'
    )
    discover_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (DEBUG level logging)'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    if args.command == 'discover':
        # Parse DNS nameservers if provided
        dns_nameservers = None
        if args.dns:
            dns_nameservers = [ns.strip() for ns in args.dns.split(',')]
        
        # Run discovery
        exit_code = asyncio.run(
            run_discovery(
                domain=args.domain,
                output=args.output,
                hackertarget_api_key=args.api_key,
                dns_nameservers=dns_nameservers,
                verbose=args.verbose
            )
        )
        
        sys.exit(exit_code)
    
    return 0


if __name__ == '__main__':
    main()
