"""
Port Scanning CLI Tool

Command-line interface for the port scanning module.
Provides easy access to port scanning functionality.
"""
import asyncio
import argparse
import logging
import sys

from .port_orchestrator import PortScanOrchestrator
from .schemas import PortScanRequest, ScanMode, ScanType


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


async def scan_ports(args):
    """Execute port scan"""
    # Parse scan mode
    scan_mode = ScanMode(args.mode)
    scan_type = ScanType(args.scan_type)
    
    # Parse targets
    targets = args.targets.split(',')
    
    # Parse custom ports if provided
    custom_ports = None
    if args.ports:
        custom_ports = [int(p.strip()) for p in args.ports.split(',')]
    
    # Build request
    request = PortScanRequest(
        targets=targets,
        mode=scan_mode,
        scan_type=scan_type,
        top_ports=args.top_ports,
        custom_ports=custom_ports,
        port_range=args.port_range,
        rate_limit=args.rate_limit,
        threads=args.threads,
        timeout=args.timeout,
        exclude_cdn=args.exclude_cdn,
        service_detection=args.service_detection,
        banner_grab=args.banner_grab,
        shodan_api_key=args.shodan_api_key
    )
    
    # Create orchestrator and run scan
    orchestrator = PortScanOrchestrator(request)
    
    print(f"\n🔍 Starting port scan for {len(targets)} target(s)...")
    print(f"Mode: {scan_mode.value}")
    print(f"Scan Type: {scan_type.value}")
    
    result = await orchestrator.run()
    
    # Display summary
    print("\n✅ Scan Complete!")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"IPs Scanned:       {result.total_ips_scanned}")
    print(f"Ports Found:       {result.total_ports_found}")
    print(f"Services ID'd:     {result.total_services_identified}")
    print(f"CDN IPs:           {result.cdn_ips_found}")
    print(f"Scan Duration:     {result.scan_duration:.2f}s")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    # Display detailed results if verbose
    if args.verbose:
        print("\n📋 Detailed Results:")
        for ip_scan in result.targets:
            print(f"\n{ip_scan.ip}:")
            if ip_scan.cdn_info and ip_scan.cdn_info.is_cdn:
                print(f"  CDN: {ip_scan.cdn_info.provider}")
            
            for port_info in ip_scan.ports:
                port_line = f"  {port_info.port}/{port_info.protocol} - {port_info.state}"
                
                if port_info.service:
                    service = port_info.service
                    if service.service_name:
                        port_line += f" ({service.service_name})"
                    if service.product and service.version:
                        port_line += f" - {service.product} {service.version}"
                    elif service.product:
                        port_line += f" - {service.product}"
                
                print(port_line)
    
    # Export to JSON if requested
    if args.output:
        orchestrator.export_json(args.output)
        print(f"\n💾 Results exported to {args.output}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Port Scanning CLI - UniVex",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single IP with top 1000 ports
  python -m app.recon.port_scanning.cli scan 192.168.1.1
  
  # Scan multiple IPs
  python -m app.recon.port_scanning.cli scan 192.168.1.1,192.168.1.2
  
  # Passive scan using Shodan
  python -m app.recon.port_scanning.cli scan 8.8.8.8 --mode passive
  
  # Hybrid scan with service detection
  python -m app.recon.port_scanning.cli scan example.com --mode hybrid --service-detection
  
  # Custom ports with banner grabbing
  python -m app.recon.port_scanning.cli scan 192.168.1.1 --ports 22,80,443 --banner-grab
  
  # Exclude CDN IPs and export results
  python -m app.recon.port_scanning.cli scan example.com --exclude-cdn --output results.json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform port scan')
    scan_parser.add_argument(
        'targets',
        help='Comma-separated list of IPs or domains to scan'
    )
    scan_parser.add_argument(
        '--mode',
        choices=['active', 'passive', 'hybrid'],
        default='active',
        help='Scan mode (default: active)'
    )
    scan_parser.add_argument(
        '--scan-type',
        choices=['syn', 'connect'],
        default='syn',
        help='Naabu scan type (default: syn)'
    )
    scan_parser.add_argument(
        '--top-ports',
        type=int,
        default=1000,
        help='Number of top ports to scan (default: 1000)'
    )
    scan_parser.add_argument(
        '--ports',
        help='Comma-separated list of specific ports to scan'
    )
    scan_parser.add_argument(
        '--port-range',
        help='Port range (e.g., "1-65535")'
    )
    scan_parser.add_argument(
        '--rate-limit',
        type=int,
        default=1000,
        help='Packets per second (default: 1000)'
    )
    scan_parser.add_argument(
        '--threads',
        type=int,
        default=25,
        help='Number of threads (default: 25)'
    )
    scan_parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Timeout in seconds (default: 10)'
    )
    scan_parser.add_argument(
        '--exclude-cdn',
        action='store_true',
        help='Exclude CDN IPs from scanning'
    )
    scan_parser.add_argument(
        '--service-detection',
        action='store_true',
        help='Perform service detection with Nmap'
    )
    scan_parser.add_argument(
        '--banner-grab',
        action='store_true',
        help='Grab service banners'
    )
    scan_parser.add_argument(
        '--shodan-api-key',
        help='Shodan API key for passive scanning'
    )
    scan_parser.add_argument(
        '--output',
        '-o',
        help='Output JSON file path'
    )
    scan_parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    setup_logging(args.verbose if hasattr(args, 'verbose') else False)
    
    if args.command == 'scan':
        asyncio.run(scan_ports(args))


if __name__ == '__main__':
    main()
