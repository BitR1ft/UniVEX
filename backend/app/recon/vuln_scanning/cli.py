"""
Vulnerability Scanning CLI

Command-line interface for vulnerability scanning module.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

import argparse
import asyncio
import json
import sys
import logging
from typing import List
from pathlib import Path

from .schemas import VulnScanRequest, ScanMode, VulnSeverity, NucleiConfig, CVEEnrichmentConfig, MITREConfig
from .vuln_orchestrator import VulnScanOrchestrator


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_argparse() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanning - Nuclei, CVE Enrichment, and MITRE Mapping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan (critical/high severity only)
  python -m app.recon.vuln_scanning.cli scan https://example.com --mode basic

  # Full scan (all templates + CVE + MITRE)
  python -m app.recon.vuln_scanning.cli scan https://example.com --mode full -v

  # Passive scan (non-intrusive checks)
  python -m app.recon.vuln_scanning.cli scan https://example.com --mode passive

  # Active DAST scan with fuzzing
  python -m app.recon.vuln_scanning.cli scan https://example.com --mode active --dast

  # CVE enrichment only (based on technologies)
  python -m app.recon.vuln_scanning.cli scan --mode cve_only --tech-file technologies.json

  # Scan from file
  python -m app.recon.vuln_scanning.cli scan -f targets.txt -o results.json

  # Custom severity and tags
  python -m app.recon.vuln_scanning.cli scan https://example.com \\
      --severity critical high --include-tags cve xss sqli -v
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run vulnerability scan')
    
    # Target specification
    target_group = scan_parser.add_mutually_exclusive_group()
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
    scan_parser.add_argument(
        '--mode',
        type=str,
        choices=['basic', 'full', 'passive', 'active', 'cve_only'],
        default='full',
        help='Scanning mode (default: full)'
    )
    
    # Nuclei options
    nuclei_group = scan_parser.add_argument_group('Nuclei options')
    nuclei_group.add_argument(
        '--severity',
        nargs='+',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default=['critical', 'high'],
        help='Severity levels to scan (default: critical high)'
    )
    nuclei_group.add_argument(
        '--include-tags',
        nargs='+',
        help='Tags to include (e.g., cve xss sqli)'
    )
    nuclei_group.add_argument(
        '--exclude-tags',
        nargs='+',
        default=['dos', 'fuzz'],
        help='Tags to exclude (default: dos fuzz)'
    )
    nuclei_group.add_argument(
        '--templates',
        type=str,
        help='Custom templates directory or file'
    )
    nuclei_group.add_argument(
        '--template-folders',
        nargs='+',
        help='Specific template folders to use'
    )
    
    # DAST options
    dast_group = scan_parser.add_argument_group('DAST options')
    dast_group.add_argument(
        '--dast',
        action='store_true',
        help='Enable DAST fuzzing mode'
    )
    dast_group.add_argument(
        '--interactsh',
        action='store_true',
        help='Enable Interactsh for blind vulnerabilities'
    )
    dast_group.add_argument(
        '--interactsh-server',
        type=str,
        help='Custom Interactsh server URL'
    )
    
    # Performance options
    perf_group = scan_parser.add_argument_group('Performance options')
    perf_group.add_argument(
        '--rate-limit',
        type=int,
        default=100,
        help='Requests per second (default: 100)'
    )
    perf_group.add_argument(
        '--concurrency',
        type=int,
        default=25,
        help='Template concurrency (default: 25)'
    )
    perf_group.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Per-request timeout in seconds (default: 10)'
    )
    perf_group.add_argument(
        '--no-headless',
        action='store_true',
        help='Disable headless browser mode'
    )
    
    # CVE enrichment options
    cve_group = scan_parser.add_argument_group('CVE enrichment options')
    cve_group.add_argument(
        '--no-cve',
        action='store_true',
        help='Disable CVE enrichment'
    )
    cve_group.add_argument(
        '--nvd-api-key',
        type=str,
        help='NVD API key for higher rate limits'
    )
    cve_group.add_argument(
        '--use-vulners',
        action='store_true',
        default=True,
        help='Use Vulners API as fallback (default: enabled)'
    )
    cve_group.add_argument(
        '--tech-file',
        type=str,
        help='JSON file with detected technologies for CVE enrichment'
    )
    cve_group.add_argument(
        '--min-cvss',
        type=float,
        default=0.0,
        help='Minimum CVSS score for CVE enrichment (default: 0.0)'
    )
    
    # MITRE mapping options
    mitre_group = scan_parser.add_argument_group('MITRE mapping options')
    mitre_group.add_argument(
        '--no-mitre',
        action='store_true',
        help='Disable MITRE CWE/CAPEC mapping'
    )
    mitre_group.add_argument(
        '--no-cwe',
        action='store_true',
        help='Disable CWE mapping'
    )
    mitre_group.add_argument(
        '--no-capec',
        action='store_true',
        help='Disable CAPEC mapping'
    )
    
    # General options
    scan_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output JSON file'
    )
    scan_parser.add_argument(
        '--no-parallel',
        action='store_true',
        help='Disable parallel execution'
    )
    scan_parser.add_argument(
        '--max-workers',
        type=int,
        default=10,
        help='Maximum parallel workers (default: 10)'
    )
    scan_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    scan_parser.add_argument(
        '--no-update',
        action='store_true',
        help='Skip template/database updates'
    )
    
    return parser


def load_targets_from_file(file_path: str) -> List[str]:
    """Load targets from a file."""
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        logger.info(f"Loaded {len(targets)} targets from {file_path}")
        return targets
    except Exception as e:
        logger.error(f"Failed to load targets from {file_path}: {e}")
        sys.exit(1)


def load_technologies_from_file(file_path: str) -> List[dict]:
    """Load detected technologies from JSON file."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        # Expect format: [{"name": "nginx", "version": "1.20.0"}, ...]
        if isinstance(data, list):
            technologies = data
        elif isinstance(data, dict) and "technologies" in data:
            technologies = data["technologies"]
        else:
            technologies = []
        logger.info(f"Loaded {len(technologies)} technologies from {file_path}")
        return technologies
    except Exception as e:
        logger.error(f"Failed to load technologies from {file_path}: {e}")
        return []


async def scan_command(args) -> None:
    """Execute vulnerability scan command."""
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load targets
    targets = []
    if args.file:
        targets = load_targets_from_file(args.file)
    elif args.targets:
        targets = args.targets
    
    # Validate targets for non-CVE-only modes
    if args.mode != 'cve_only' and not targets:
        logger.error("No targets specified. Use positional arguments or -f/--file")
        sys.exit(1)
    
    # Load technologies if provided
    detected_technologies = []
    if args.tech_file:
        detected_technologies = load_technologies_from_file(args.tech_file)
    
    # Build Nuclei configuration
    severity_map = {
        'critical': VulnSeverity.CRITICAL,
        'high': VulnSeverity.HIGH,
        'medium': VulnSeverity.MEDIUM,
        'low': VulnSeverity.LOW,
        'info': VulnSeverity.INFO,
    }
    
    nuclei_config = NucleiConfig(
        templates_path=args.templates,
        severity_filter=[severity_map[s] for s in args.severity],
        include_tags=args.include_tags or [],
        exclude_tags=args.exclude_tags,
        template_folders=args.template_folders or [],
        dast_enabled=args.dast,
        interactsh_enabled=args.interactsh,
        interactsh_server=args.interactsh_server,
        rate_limit=args.rate_limit,
        concurrency=args.concurrency,
        timeout=args.timeout,
        headless_mode=not args.no_headless,
        auto_update_templates=not args.no_update,
    )
    
    # Build CVE enrichment configuration
    cve_config = CVEEnrichmentConfig(
        enabled=not args.no_cve,
        nvd_api_key=args.nvd_api_key,
        use_vulners=args.use_vulners,
        min_cvss_score=args.min_cvss,
    )
    
    # Build MITRE configuration
    mitre_config = MITREConfig(
        enabled=not args.no_mitre,
        cve_to_cwe=not args.no_cwe,
        cwe_to_capec=not args.no_capec,
        auto_update_db=not args.no_update,
    )
    
    # Build scan request
    try:
        request = VulnScanRequest(
            targets=targets,
            mode=ScanMode(args.mode),
            nuclei_config=nuclei_config,
            cve_enrichment=cve_config,
            mitre_mapping=mitre_config,
            detected_technologies=detected_technologies,
            parallel_execution=not args.no_parallel,
            max_workers=args.max_workers,
        )
    except Exception as e:
        logger.error(f"Failed to build scan request: {e}")
        sys.exit(1)
    
    # Execute scan
    try:
        logger.info("=" * 80)
        logger.info("Starting Vulnerability Scan")
        logger.info("=" * 80)
        
        orchestrator = VulnScanOrchestrator(request)
        result = await orchestrator.run()
        
        # Display results
        print("\n" + "=" * 80)
        print("📊 VULNERABILITY SCAN RESULTS")
        print("=" * 80)
        print(f"Mode: {result.request.mode.value}")
        print(f"Targets: {len(result.request.targets)}")
        print(f"Total Vulnerabilities: {result.stats.total_vulnerabilities}")
        print(f"Execution Time: {result.stats.execution_time:.2f}s")
        
        if result.stats.by_severity:
            print("\n🔴 By Severity:")
            for severity, count in sorted(result.stats.by_severity.items(), reverse=True):
                print(f"  {severity.upper()}: {count}")
        
        if result.stats.by_category:
            print("\n📂 By Category:")
            for category, count in sorted(result.stats.by_category.items(), key=lambda x: x[1], reverse=True):
                print(f"  {category}: {count}")
        
        if result.stats.by_source:
            print("\n🔍 By Source:")
            for source, count in result.stats.by_source.items():
                print(f"  {source}: {count}")
        
        print("\n⏱️  Performance:")
        print(f"  Nuclei Scan: {result.stats.nuclei_time:.2f}s")
        print(f"  CVE Enrichment: {result.stats.enrichment_time:.2f}s")
        print(f"  MITRE Mapping: {result.stats.mitre_time:.2f}s")
        
        if result.stats.cves_enriched > 0:
            print("\n🔬 Enrichment:")
            print(f"  CVEs Enriched: {result.stats.cves_enriched}")
            print(f"  CWEs Mapped: {result.stats.cwes_mapped}")
            print(f"  CAPECs Mapped: {result.stats.capecs_mapped}")
        
        # Show sample vulnerabilities
        if result.vulnerabilities:
            print("\n🎯 Sample Vulnerabilities (Top 10):")
            for i, vuln in enumerate(result.vulnerabilities[:10], 1):
                cve_info = f" ({vuln.cve.cve_id})" if vuln.cve else ""
                print(f"  {i}. [{vuln.severity.value.upper()}] {vuln.title}{cve_info}")
                print(f"     Source: {vuln.source} | Category: {vuln.category.value}")
                if vuln.matched_at:
                    print(f"     Found at: {vuln.matched_at}")
        
        if result.errors:
            print(f"\n⚠️  Errors ({len(result.errors)}):")
            for error in result.errors[:5]:
                print(f"  - {error}")
        
        if result.warnings:
            print(f"\n⚡ Warnings ({len(result.warnings)}):")
            for warning in result.warnings[:5]:
                print(f"  - {warning}")
        
        # Save to file
        if args.output:
            output_path = Path(args.output)
            with open(output_path, 'w') as f:
                json.dump(result.model_dump(mode='json'), f, indent=2, default=str)
            print(f"\n💾 Results saved to: {output_path}")
        
        print("=" * 80)
        
        # Exit with appropriate code
        sys.exit(0 if result.success else 1)
        
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=args.verbose)
        sys.exit(1)


def main():
    """Main entry point."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if args.command == 'scan':
        asyncio.run(scan_command(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
