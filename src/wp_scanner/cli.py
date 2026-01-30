#!/usr/bin/env python3
"""
WordPress Security Scanner Suite - CLI Entry Point
Professional security assessment tool for WordPress sites.
"""

import sys
import argparse
from pathlib import Path

from wp_scanner import WPSecurityScanner, BatchScanner, __version__


BANNER = f"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   WordPress Security Scanner Suite v{__version__:<24}║
║   Professional Security Assessment Tool                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""

DISCLAIMER = """
╔═══════════════════════════════════════════════════════════════╗
║  LEGAL DISCLAIMER                                             ║
╠═══════════════════════════════════════════════════════════════╣
║  This tool is for AUTHORIZED security testing ONLY.           ║
║  You must have explicit written permission to scan targets.   ║
║  Unauthorized scanning may violate computer crime laws.       ║
╚═══════════════════════════════════════════════════════════════╝
"""


def scan_single(args):
    """Execute single target scan."""
    # Aggressive is default, --passive disables it
    aggressive = not getattr(args, 'passive', False)

    with WPSecurityScanner(
        args.url,
        aggressive=aggressive,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
        output_dir=args.output
    ) as scanner:
        scanner.scan()
        scanner.print_report()

        if args.export:
            reports = scanner.export_reports()
            print(f"\nReports saved:")
            for fmt, path in reports.items():
                print(f"  {fmt}: {path}")


def scan_batch(args):
    """Execute batch scan on multiple targets."""
    targets = []

    if args.targets_file:
        targets_path = Path(args.targets_file)
        if not targets_path.exists():
            print(f"Error: Targets file not found: {args.targets_file}")
            sys.exit(1)

        with open(targets_path, 'r') as f:
            targets.extend([
                line.strip() for line in f
                if line.strip() and not line.startswith('#')
            ])

    if args.urls:
        targets.extend(args.urls)

    if not targets:
        print("Error: No targets specified")
        print("Use -t <file> or -u <url> [url2] ...")
        sys.exit(1)

    # Remove duplicates while preserving order
    targets = list(dict.fromkeys(targets))

    print(f"Loaded {len(targets)} target(s)")

    # Aggressive is default, --passive disables it
    aggressive = not getattr(args, 'passive', False)

    scanner = BatchScanner(
        targets,
        aggressive=aggressive,
        threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output
    )

    scanner.scan_all()
    scanner.print_summary()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='wordpress-scan',
        description='WordPress Security Scanner Suite - Professional Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  wordpress-scan scan https://example.com              # Basic scan
  wordpress-scan scan https://example.com --aggressive # Full assessment
  wordpress-scan batch -t targets.txt                  # Batch from file
  wordpress-scan batch -u site1.com site2.com -a       # Batch with URLs

Output:
  Reports are saved to ./output by default in JSON, Markdown, and CSV formats.

For more information: https://github.com/wp-scanner/suite
        """
    )

    parser.add_argument(
        '--version', '-V',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    subparsers = parser.add_subparsers(
        dest='command',
        title='commands',
        description='Available scan modes'
    )

    # Single scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Scan a single WordPress target',
        description='Perform comprehensive security assessment on a single site'
    )
    scan_parser.add_argument(
        'url',
        help='Target URL (e.g., https://example.com)'
    )
    scan_parser.add_argument(
        '--aggressive', '-a',
        action='store_true',
        default=True,
        help='Enable aggressive scanning (default: enabled)'
    )
    scan_parser.add_argument(
        '--passive', '-p',
        action='store_true',
        help='Disable aggressive scanning (passive mode only)'
    )
    scan_parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=15,
        metavar='SEC',
        help='Request timeout in seconds (default: 15)'
    )
    scan_parser.add_argument(
        '--threads',
        type=int,
        default=10,
        metavar='N',
        help='Concurrent threads for file scanning (default: 10)'
    )
    scan_parser.add_argument(
        '--output', '-o',
        default='output',
        metavar='DIR',
        help='Output directory for reports (default: output)'
    )
    scan_parser.add_argument(
        '--export', '-e',
        action='store_true',
        help='Export reports to files after scan'
    )
    scan_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    scan_parser.add_argument(
        '--yes', '-y',
        action='store_true',
        help='Skip authorization confirmation (for automation)'
    )

    # Batch scan command
    batch_parser = subparsers.add_parser(
        'batch',
        help='Scan multiple WordPress targets',
        description='Scan multiple sites with consolidated reporting'
    )
    batch_parser.add_argument(
        '-t', '--targets-file',
        metavar='FILE',
        help='File containing target URLs (one per line)'
    )
    batch_parser.add_argument(
        '-u', '--urls',
        nargs='+',
        metavar='URL',
        help='Target URLs to scan'
    )
    batch_parser.add_argument(
        '--aggressive', '-a',
        action='store_true',
        default=True,
        help='Enable aggressive scanning (default: enabled)'
    )
    batch_parser.add_argument(
        '--passive', '-p',
        action='store_true',
        help='Disable aggressive scanning (passive mode only)'
    )
    batch_parser.add_argument(
        '--timeout',
        type=int,
        default=15,
        metavar='SEC',
        help='Request timeout per target (default: 15)'
    )
    batch_parser.add_argument(
        '--threads',
        type=int,
        default=2,
        metavar='N',
        help='Concurrent target scans (default: 2)'
    )
    batch_parser.add_argument(
        '--output', '-o',
        default='output',
        metavar='DIR',
        help='Output directory for reports (default: output)'
    )
    batch_parser.add_argument(
        '--yes', '-y',
        action='store_true',
        help='Skip authorization confirmation (for automation)'
    )

    args = parser.parse_args()

    if not args.command:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    print(BANNER)
    print(DISCLAIMER)

    # Authorization confirmation (skip with --yes flag)
    if not getattr(args, 'yes', False):
        try:
            confirm = input("Do you have authorization to scan the target(s)? (yes/no): ")
            if confirm.lower() not in ('yes', 'y'):
                print("\nExiting. Obtain proper authorization first.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print("\n\nScan cancelled.")
            sys.exit(0)
    else:
        print("[!] Authorization confirmed via --yes flag\n")

    print()

    try:
        if args.command == 'scan':
            scan_single(args)
        elif args.command == 'batch':
            scan_batch(args)
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
