"""
Base scanner class that all specific scanners inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from wp_scanner.utils.http import HTTPClient
from wp_scanner.utils.logger import Logger


class BaseScanner(ABC):
    """Abstract base class for all scanner modules."""

    def __init__(self, http_client: HTTPClient, logger: Logger):
        """
        Initialize scanner.

        Args:
            http_client: HTTP client for making requests
            logger: Logger instance for output
        """
        self.http = http_client
        self.log = logger
        self.findings: List[Dict[str, Any]] = []

    def add_finding(self, severity: str, title: str, description: str,
                    remediation: str, cve: str = None, cvss: float = None,
                    evidence: str = None):
        """Add a vulnerability finding."""
        self.findings.append({
            'severity': severity.upper(),
            'title': title,
            'description': description,
            'remediation': remediation,
            'cve': cve,
            'cvss': cvss,
            'evidence': evidence,
        })

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings from this scanner."""
        return self.findings

    def clear_findings(self):
        """Clear all findings."""
        self.findings = []

    @abstractmethod
    def scan(self, **kwargs) -> Dict[str, Any]:
        """
        Run the scan. Must be implemented by subclasses.

        Returns:
            Dictionary with scan results
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name for logging."""
        pass
