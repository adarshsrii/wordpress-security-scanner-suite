"""Vulnerability database modules."""

from wp_scanner.databases.vuln_db import UnifiedVulnDatabase, WPVulnerabilityClient
from wp_scanner.databases.plugin_db import (
    VULNERABLE_PLUGINS,
    check_plugin_vulnerability,
    get_critical_plugins
)

__all__ = [
    "UnifiedVulnDatabase",
    "WPVulnerabilityClient",
    "VULNERABLE_PLUGINS",
    "check_plugin_vulnerability",
    "get_critical_plugins"
]
