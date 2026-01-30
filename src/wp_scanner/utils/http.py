"""
HTTP Client utility with retry logic, rate limiting, and session management.
Thread-safe implementation with connection pooling for parallel scanning.
"""

import time
import threading
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any
from urllib.parse import urljoin
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class HTTPClient:
    """Thread-safe HTTP client with connection pooling and built-in protections."""

    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

    def __init__(self, base_url: str = "", timeout: int = 10,
                 max_retries: int = 3, rate_limit: float = 0.1,
                 verify_ssl: bool = False, user_agent: str = None,
                 pool_connections: int = 10, pool_maxsize: int = 20):
        """
        Initialize HTTP client.

        Args:
            base_url: Base URL for all requests
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
            rate_limit: Minimum seconds between requests
            verify_ssl: Whether to verify SSL certificates
            user_agent: Custom User-Agent string
            pool_connections: Number of connection pools to cache
            pool_maxsize: Maximum connections per pool (for thread safety)
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl
        self._last_request_time = 0
        self._lock = threading.Lock()

        # Setup session with connection pooling
        self.session = requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)

        if user_agent:
            self.session.headers['User-Agent'] = user_agent

        # Configure connection pooling for thread safety
        retry_strategy = Retry(
            total=0,  # We handle retries ourselves
            backoff_factor=0,
        )
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy,
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # Thread-safe request statistics
        self._stats_lock = threading.Lock()
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'retries': 0,
        }

    def _rate_limit_wait(self):
        """Enforce rate limiting between requests (thread-safe)."""
        with self._lock:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self._last_request_time = time.time()

    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        if path.startswith(('http://', 'https://')):
            return path
        return urljoin(self.base_url + '/', path.lstrip('/'))

    def request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """
        Make an HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path or full URL
            **kwargs: Additional arguments passed to requests

        Returns:
            Response object or None if all retries failed
        """
        url = self._build_url(path)
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)

        last_exception = None

        for attempt in range(self.max_retries):
            try:
                self._rate_limit_wait()
                with self._stats_lock:
                    self.stats['total_requests'] += 1

                response = self.session.request(method, url, **kwargs)
                with self._stats_lock:
                    self.stats['successful_requests'] += 1
                return response

            except requests.exceptions.Timeout:
                last_exception = "Request timed out"
                with self._stats_lock:
                    self.stats['retries'] += 1
            except requests.exceptions.ConnectionError:
                last_exception = "Connection error"
                with self._stats_lock:
                    self.stats['retries'] += 1
            except requests.exceptions.RequestException as e:
                last_exception = str(e)
                with self._stats_lock:
                    self.stats['retries'] += 1

            # Exponential backoff
            if attempt < self.max_retries - 1:
                time.sleep(2 ** attempt)

        with self._stats_lock:
            self.stats['failed_requests'] += 1
        return None

    def get(self, path: str, **kwargs) -> Optional[requests.Response]:
        """Make a GET request."""
        return self.request('GET', path, **kwargs)

    def post(self, path: str, **kwargs) -> Optional[requests.Response]:
        """Make a POST request."""
        return self.request('POST', path, **kwargs)

    def head(self, path: str, **kwargs) -> Optional[requests.Response]:
        """Make a HEAD request."""
        return self.request('HEAD', path, **kwargs)

    def options(self, path: str, **kwargs) -> Optional[requests.Response]:
        """Make an OPTIONS request."""
        return self.request('OPTIONS', path, **kwargs)

    def get_json(self, path: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make a GET request and parse JSON response."""
        response = self.get(path, **kwargs)
        if response and response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return None
        return None

    def check_exists(self, path: str) -> bool:
        """Check if a URL exists (returns 200)."""
        response = self.head(path, allow_redirects=True)
        return response is not None and response.status_code == 200

    def get_stats(self) -> Dict[str, int]:
        """Get request statistics (thread-safe)."""
        with self._stats_lock:
            return self.stats.copy()

    def reset_stats(self):
        """Reset request statistics (thread-safe)."""
        with self._stats_lock:
            self.stats = {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'retries': 0,
            }

    def close(self):
        """Close the session."""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
