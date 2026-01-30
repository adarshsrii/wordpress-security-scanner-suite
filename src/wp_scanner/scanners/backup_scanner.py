"""
Backup and sensitive file exposure scanner.
Checks 130+ common backup and configuration file paths.
"""

from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from wp_scanner.scanners.base import BaseScanner
from wp_scanner.payloads import BACKUP_FILES


class BackupFileScanner(BaseScanner):
    """Scanner for exposed backup and configuration files."""

    @property
    def name(self) -> str:
        return "Backup File Scanner"

    def _get_severity(self, path: str) -> str:
        """Determine severity based on file type."""
        path_lower = path.lower()

        critical_patterns = [
            'wp-config', '.env', '.sql', 'backup', 'dump',
            '.git', 'passwd', 'shadow', 'phpmyadmin'
        ]
        if any(p in path_lower for p in critical_patterns):
            return 'CRITICAL'

        high_patterns = [
            'phpinfo', 'info.php', '.htpasswd', 'php.ini',
            '.svn', '.hg', 'debug.log', 'error.log'
        ]
        if any(p in path_lower for p in high_patterns):
            return 'HIGH'

        medium_patterns = [
            'readme', 'license', 'composer', 'package.json',
            '.htaccess', '.idea', '.vscode'
        ]
        if any(p in path_lower for p in medium_patterns):
            return 'MEDIUM'

        return 'LOW'

    def _check_file(self, path: str) -> Dict[str, Any]:
        """Check if a single file is accessible."""
        response = self.http.head(path, allow_redirects=True)

        if response and response.status_code == 200:
            # Verify with GET
            get_response = self.http.get(path)
            if get_response and get_response.status_code == 200:
                content_length = len(get_response.content)
                if content_length > 0:
                    return {
                        'path': path,
                        'size': content_length,
                        'content_type': get_response.headers.get('Content-Type', ''),
                        'severity': self._get_severity(path),
                    }
        return None

    def scan(self, threads: int = 10, file_list: List[str] = None) -> Dict[str, Any]:
        """
        Scan for exposed backup and sensitive files.

        Args:
            threads: Number of concurrent threads
            file_list: Optional custom file list (defaults to BACKUP_FILES)

        Returns:
            Dictionary with exposed files and vulnerabilities
        """
        files_to_check = file_list or BACKUP_FILES
        self.log.scan(f"Checking {len(files_to_check)} backup/config file paths...")

        exposed_files = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_file, path): path
                for path in files_to_check
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    exposed_files.append(result)

                    severity = result['severity']
                    if severity == 'CRITICAL':
                        self.log.critical(f"Exposed: {result['path']} ({result['size']} bytes)")
                    else:
                        self.log.warning(f"Exposed: {result['path']} ({result['size']} bytes)")

                    self.add_finding(
                        severity,
                        f"Exposed Sensitive File: {result['path']}",
                        f"Sensitive file accessible. Size: {result['size']} bytes, "
                        f"Content-Type: {result['content_type']}",
                        f"Remove or restrict access to {result['path']}. "
                        "Add to .htaccess:\n"
                        f"<Files \"{result['path'].split('/')[-1]}\">\n"
                        "Order allow,deny\nDeny from all\n</Files>",
                        evidence=f"HTTP 200, {result['size']} bytes"
                    )

        self.log.info(f"Found {len(exposed_files)} exposed files out of {len(files_to_check)} checked")

        return {
            'exposed_files': exposed_files,
            'total_checked': len(files_to_check),
            'findings': self.get_findings(),
        }
