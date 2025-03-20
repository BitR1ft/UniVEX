"""
HTTP Probing CLI - Month 5

Command-line interface for HTTP probing functionality.
"""

import asyncio
import argparse
import json
import sys
from typing import List
import logging

from .http_orchestrator import HttpProbeOrchestrator
from .schemas import HttpProbeRequest, ProbeMode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='HTTP Probing Tool - Comprehensive web technology detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic probe
  python -m app.recon.http_probing.cli probe https://example.com
  
  # Probe multiple targets
  python -m app.recon.http_probing.cli probe https://site1.com https://site2.com
  
  # Full probe with all features
  python -m app.recon.http_probing.cli probe https://example.com --mode full
  
  # Probe from file
  python -m app.recon.http_probing.cli probe -f targets.txt
  
  # Disable Wappalyzer
  python -m app.recon.http_probing.cli probe https://example.com --no-wappalyzer
  
  # Save output to JSON
  python -m app.recon.http_probing.cli probe https://example.com -o results.json
        """
    )
    
    parser.add_argument(
        'command',
        choices=['probe'],
        help='Command to execute'
    )
    
    parser.add_argument(
        'targets',
        nargs='*',
        help='Target URLs to probe'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='File containing target URLs (one per line)'
    )
    
    parser.add_argument(
        '-m', '--mode',
        choices=['basic', 'full', 'stealth'],
        default='full',
        help='Probing mode (default: full)'
    )
    
    parser.add_argument(
        '--no-redirects',
        action='store_true',
        help='Do not follow HTTP redirects'
    )
    
    parser.add_argument(
        '--max-redirects',
        type=int,
        default=10,
        help='Maximum redirect chains (default: 10)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Concurrent threads (default: 50)'
    )
    
    parser.add_argument(
        '--no-tech',
        action='store_true',
        help='Disable technology detection'
    )
    
    parser.add_argument(
        '--no-wappalyzer',
        action='store_true',
        help='Disable Wappalyzer (use httpx only)'
    )
    
    parser.add_argument(
        '--no-tls',
        action='store_true',
        help='Disable TLS inspection'
    )
    
    parser.add_argument(
        '--no-favicon',
        action='store_true',
        help='Disable favicon hashing'
    )
    
    parser.add_argument(
        '--screenshot',
        action='store_true',
        help='Capture screenshots (requires additional tools)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file (JSON format)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    return parser.parse_args()


def load_targets(args) -> List[str]:
    """Load targets from command line or file"""
    targets = []
    
    # From command line
    if args.targets:
        targets.extend(args.targets)
    
    # From file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip()]
                targets.extend(file_targets)
        except Exception as e:
            logger.error(f"Failed to read targets from file: {e}")
            sys.exit(1)
    
    if not targets:
        logger.error("No targets specified. Use targets as arguments or -f file")
        sys.exit(1)
    
    return targets


async def probe_command(args):
    """Execute probe command"""
    targets = load_targets(args)
    
    logger.info(f"Starting HTTP probe for {len(targets)} target(s)")
    
    # Build request
    request = HttpProbeRequest(
        targets=targets,
        mode=ProbeMode(args.mode),
        follow_redirects=not args.no_redirects,
        max_redirects=args.max_redirects,
        timeout=args.timeout,
        threads=args.threads,
        tech_detection=not args.no_tech,
        wappalyzer=not args.no_wappalyzer,
        screenshot=args.screenshot,
        favicon_hash=not args.no_favicon,
        tls_inspection=not args.no_tls,
        jarm_fingerprint=not args.no_tls,
        security_headers=True
    )
    
    # Execute probe
    orchestrator = HttpProbeOrchestrator(request)
    result = await orchestrator.run()
    
    # Display results
    display_results(result, args.verbose)
    
    # Save to file if requested
    if args.output:
        save_results(result, args.output)
    
    logger.info(f"Probe completed in {result.stats.duration_seconds:.2f} seconds")


def display_results(result, verbose=False):
    """Display probe results to console"""
    print("\n" + "="*80)
    print("HTTP PROBE RESULTS")
    print("="*80)
    
    # Statistics
    stats = result.stats
    print("\nStatistics:")
    print(f"  Total Targets:        {stats.total_targets}")
    print(f"  Successful Probes:    {stats.successful_probes}")
    print(f"  Failed Probes:        {stats.failed_probes}")
    print(f"  HTTPS Count:          {stats.https_count}")
    print(f"  HTTP Count:           {stats.http_count}")
    print(f"  Redirects:            {stats.redirect_count}")
    print(f"  Technologies Found:   {stats.unique_technologies}")
    print(f"  CDN Detected:         {stats.cdn_count}")
    print(f"  TLS Inspected:        {stats.tls_count}")
    if stats.avg_response_time_ms:
        print(f"  Avg Response Time:    {stats.avg_response_time_ms:.2f} ms")
    
    # Individual results
    print("\nTarget Results:")
    for idx, target in enumerate(result.results, 1):
        print(f"\n  [{idx}] {target.url}")
        
        if not target.success:
            print(f"      Status: FAILED - {target.error}")
            continue
        
        print(f"      Status: {target.status_code} {target.status_text}")
        print(f"      Scheme: {target.scheme}")
        print(f"      Host: {target.host}:{target.port}")
        
        if target.final_url != target.url:
            print(f"      Final URL: {target.final_url}")
        
        if target.response_time_ms:
            print(f"      Response Time: {target.response_time_ms:.2f} ms")
        
        if target.server_header:
            print(f"      Server: {target.server_header}")
        
        if target.content and target.content.title:
            print(f"      Title: {target.content.title}")
        
        # Technologies
        if target.technologies:
            print(f"      Technologies ({len(target.technologies)}):")
            for tech in target.technologies[:5]:  # Show first 5
                version = f" {tech.version}" if tech.version else ""
                print(f"        - {tech.name}{version} [{tech.category}] ({tech.confidence}%)")
            if len(target.technologies) > 5:
                print(f"        ... and {len(target.technologies) - 5} more")
        
        # TLS info
        if target.tls and target.tls.certificate:
            cert = target.tls.certificate
            print("      TLS Certificate:")
            print(f"        Issuer: {cert.issuer}")
            print(f"        Expires: {cert.not_after}")
            print(f"        Days Until Expiry: {cert.days_until_expiry}")
            if cert.is_expired:
                print("        WARNING: Certificate is EXPIRED")
        
        # Security headers
        if target.security_headers and verbose:
            print(f"      Security Score: {target.security_headers.security_score}/100")
            if target.security_headers.missing_headers:
                print(f"      Missing Headers: {', '.join(target.security_headers.missing_headers)}")
        
        # Favicon
        if target.favicon and verbose:
            print("      Favicon:")
            print(f"        MD5: {target.favicon.md5}")
            if target.favicon.mmh3:
                print(f"        MMH3: {target.favicon.mmh3}")
    
    print("\n" + "="*80 + "\n")


def save_results(result, output_file):
    """Save results to JSON file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Results saved to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")


async def main():
    """Main entry point"""
    args = parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.command == 'probe':
        await probe_command(args)


if __name__ == '__main__':
    asyncio.run(main())
