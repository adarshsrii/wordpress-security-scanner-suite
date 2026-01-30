#!/usr/bin/env python3
"""
Batch WordPress Security Scanner
Scan multiple WordPress sites with comprehensive reporting.
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from wp_scanner.core.scanner import WPSecurityScanner
from wp_scanner.utils.logger import setup_logger
from wp_scanner.utils.reporter import ReportGenerator


class BatchScanner:
    """Batch scanner for multiple WordPress sites."""

    def __init__(self, targets: List[str], aggressive: bool = False,
                 threads: int = 2, timeout: int = 15,
                 output_dir: str = "output"):
        """
        Initialize batch scanner.

        Args:
            targets: List of target URLs
            aggressive: Enable aggressive scanning
            threads: Number of concurrent scans
            timeout: Request timeout per target
            output_dir: Directory for results
        """
        self.targets = [self._normalize_url(t) for t in targets]
        self.aggressive = aggressive
        self.threads = threads
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.log = setup_logger()

        self.results = {
            'scan_time': datetime.now().isoformat(),
            'total_targets': len(targets),
            'completed': 0,
            'failed': 0,
            'wordpress_sites': 0,
            'output_directory': str(self.output_dir.absolute()),
            'scan_results': [],
            'summary': {
                'critical_vulns': 0,
                'high_vulns': 0,
                'medium_vulns': 0,
                'low_vulns': 0,
                'exposed_files': 0,
                'average_score': 0
            }
        }

    def _normalize_url(self, url: str) -> str:
        """Normalize URL format."""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL (human-readable)."""
        parsed = urlparse(url)
        return parsed.netloc

    def _get_folder_name(self, url: str) -> str:
        """Extract domain from URL for folder names (preserves dots)."""
        parsed = urlparse(url)
        # Only replace colon (for ports), keep dots for readability
        return parsed.netloc.replace(':', '_')

    def scan_target(self, target: str) -> Dict[str, Any]:
        """Scan a single target."""
        domain = self._get_domain(target)
        folder_name = self._get_folder_name(target)
        target_dir = self.output_dir / folder_name
        target_dir.mkdir(parents=True, exist_ok=True)

        self.log.banner(f"Scanning: {domain}", char="-", width=50)

        try:
            with WPSecurityScanner(
                target,
                aggressive=self.aggressive,
                timeout=self.timeout,
                output_dir=str(self.output_dir)
            ) as scanner:
                results = scanner.scan()
                scanner.calculate_risk_score()
                scanner.generate_recommendations()

                # Export reports
                reports = scanner.export_reports()

                return {
                    'target': target,
                    'domain': domain,
                    'folder_name': folder_name,
                    'status': 'completed',
                    'is_wordpress': results['is_wordpress'],
                    'wordpress_version': results.get('wordpress_version'),
                    'risk_score': results.get('risk_score', 0),
                    'grade': scanner.get_grade(),
                    'vulnerabilities': {
                        'critical': len(results['vulnerabilities']['critical']),
                        'high': len(results['vulnerabilities']['high']),
                        'medium': len(results['vulnerabilities']['medium']),
                        'low': len(results['vulnerabilities']['low']),
                    },
                    'exposed_files': len(results.get('exposed_files', [])),
                    'plugins_found': len(results.get('plugins', {})),
                    'themes_found': len(results.get('themes', {})),
                    'users_found': len(results.get('users', [])),
                    'reports': reports,
                    'full_results': results
                }

        except Exception as e:
            error_file = target_dir / 'error.log'
            with open(error_file, 'w') as f:
                f.write(f"Scan failed at {datetime.now().isoformat()}\n")
                f.write(f"Error: {str(e)}\n")

            return {
                'target': target,
                'domain': domain,
                'folder_name': folder_name,
                'status': 'failed',
                'error': str(e),
                'is_wordpress': False,
                'risk_score': 0
            }

    def scan_all(self) -> Dict[str, Any]:
        """Scan all targets."""
        self.log.banner("BATCH SECURITY SCANNER", width=60)
        self.log.info(f"Targets: {len(self.targets)}")
        self.log.info(f"Mode: {'AGGRESSIVE' if self.aggressive else 'PASSIVE'}")
        self.log.info(f"Output: {self.output_dir.absolute()}")
        print()

        total_score = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.scan_target, target): target
                for target in self.targets
            }

            for future in as_completed(futures):
                result = future.result()
                self.results['scan_results'].append(result)

                if result['status'] == 'completed':
                    self.results['completed'] += 1
                    if result['is_wordpress']:
                        self.results['wordpress_sites'] += 1
                        total_score += result['risk_score']

                        self.results['summary']['critical_vulns'] += result['vulnerabilities']['critical']
                        self.results['summary']['high_vulns'] += result['vulnerabilities']['high']
                        self.results['summary']['medium_vulns'] += result['vulnerabilities']['medium']
                        self.results['summary']['low_vulns'] += result['vulnerabilities']['low']
                        self.results['summary']['exposed_files'] += result['exposed_files']
                else:
                    self.results['failed'] += 1

                self.log.progress(
                    self.results['completed'] + self.results['failed'],
                    len(self.targets),
                    prefix="Progress"
                )

        if self.results['wordpress_sites'] > 0:
            self.results['summary']['average_score'] = \
                round(total_score / self.results['wordpress_sites'], 1)

        self._save_batch_reports()

        return self.results

    def _save_batch_reports(self):
        """Save consolidated batch reports to batch/ folder (always override)."""
        batch_dir = self.output_dir / 'batch'
        batch_dir.mkdir(parents=True, exist_ok=True)

        # JSON summary
        json_file = batch_dir / 'summary.json'
        export_data = {
            **self.results,
            'scan_results': [
                {k: v for k, v in r.items() if k != 'full_results'}
                for r in self.results['scan_results']
            ]
        }
        with open(json_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        # CSV summary
        csv_file = batch_dir / 'summary.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Target', 'Status', 'WordPress', 'Version', 'Score', 'Grade',
                'Critical', 'High', 'Medium', 'Low', 'Exposed Files', 'Plugins'
            ])
            for r in self.results['scan_results']:
                if r['status'] == 'completed':
                    writer.writerow([
                        r['target'], r['status'], r['is_wordpress'],
                        r.get('wordpress_version', 'N/A'),
                        r.get('risk_score', 'N/A'), r.get('grade', 'N/A'),
                        r['vulnerabilities']['critical'], r['vulnerabilities']['high'],
                        r['vulnerabilities']['medium'], r['vulnerabilities']['low'],
                        r['exposed_files'], r['plugins_found']
                    ])

        # Markdown summary
        md_file = batch_dir / 'summary.md'
        self._save_batch_markdown(md_file)

        self.log.success(f"Batch reports saved to {batch_dir}")

    def _save_batch_markdown(self, filepath: Path):
        """Save batch markdown report."""
        md = f"""# Batch WordPress Security Scan

**Scan Time:** {self.results['scan_time']}
**Total Targets:** {self.results['total_targets']}
**WordPress Sites:** {self.results['wordpress_sites']}
**Average Score:** {self.results['summary']['average_score']}/100

## Summary

| Metric | Value |
|--------|-------|
| Completed | {self.results['completed']} |
| Failed | {self.results['failed']} |
| Critical Vulns | {self.results['summary']['critical_vulns']} |
| High Vulns | {self.results['summary']['high_vulns']} |
| Exposed Files | {self.results['summary']['exposed_files']} |

## Results

| Target | Score | Grade | Critical | High | Plugins |
|--------|-------|-------|----------|------|---------|
"""
        for r in sorted(self.results['scan_results'], key=lambda x: x.get('risk_score', 0)):
            if r['status'] == 'completed' and r['is_wordpress']:
                md += f"| {r['domain']} | {r['risk_score']} | {r['grade']} | "
                md += f"{r['vulnerabilities']['critical']} | {r['vulnerabilities']['high']} | "
                md += f"{r['plugins_found']} |\n"

        md += f"\n---\n*Generated by WordPress Security Scanner Suite*\n"

        with open(filepath, 'w') as f:
            f.write(md)

    def print_summary(self):
        """Print summary to console."""
        self.log.banner("BATCH SCAN COMPLETE", width=60)

        print(f"Targets Scanned: {self.results['total_targets']}")
        print(f"Completed: {self.results['completed']}")
        print(f"Failed: {self.results['failed']}")
        print(f"WordPress Sites: {self.results['wordpress_sites']}")
        print()

        self.log.section("Vulnerability Totals")
        print(f"  Critical: {self.results['summary']['critical_vulns']}")
        print(f"  High:     {self.results['summary']['high_vulns']}")
        print(f"  Medium:   {self.results['summary']['medium_vulns']}")
        print(f"  Low:      {self.results['summary']['low_vulns']}")
        print()

        print(f"Average Score: {self.results['summary']['average_score']}/100")
        print()

        self.log.section("Per-Target Results")
        print(f"{'Domain':<30} {'Score':<7} {'Grade':<6} {'Crit':<6}")
        print("-" * 55)

        for r in sorted(self.results['scan_results'], key=lambda x: x.get('risk_score', 0)):
            if r['status'] == 'completed' and r['is_wordpress']:
                print(f"{r['domain'][:28]:<30} {r['risk_score']:<7} {r['grade']:<6} "
                      f"{r['vulnerabilities']['critical']:<6}")

        print()
        self.log.info(f"Results saved to: {self.output_dir.absolute()}")
