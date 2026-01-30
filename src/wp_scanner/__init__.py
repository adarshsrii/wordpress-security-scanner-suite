"""
WordPress Security Scanner Suite
A professional-grade security assessment tool for WordPress installations.

Author: Security Scanner Suite
Version: 2.0.0
"""

__version__ = "2.0.0"
__author__ = "Security Scanner Suite"

from wp_scanner.core.scanner import WPSecurityScanner
from wp_scanner.core.batch import BatchScanner

__all__ = ["WPSecurityScanner", "BatchScanner", "__version__"]
