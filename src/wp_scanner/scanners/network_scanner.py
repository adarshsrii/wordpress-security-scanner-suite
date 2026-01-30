"""
Network-level security scanner.
Checks for open ports, subdomain takeover, DNSSEC, CAA records, etc.
"""

import socket
import ssl
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from wp_scanner.scanners.base import BaseScanner


class NetworkScanner(BaseScanner):
    """Network-level security checks."""

    # Common vulnerable ports to check
    COMMON_PORTS = {
        21: ('FTP', 'HIGH', 'File transfer, often unencrypted'),
        22: ('SSH', 'INFO', 'Secure shell - ensure key-based auth'),
        23: ('Telnet', 'CRITICAL', 'Unencrypted remote access'),
        25: ('SMTP', 'LOW', 'Mail server'),
        53: ('DNS', 'INFO', 'DNS server'),
        110: ('POP3', 'MEDIUM', 'Email retrieval, often unencrypted'),
        143: ('IMAP', 'MEDIUM', 'Email access, often unencrypted'),
        445: ('SMB', 'HIGH', 'Windows file sharing'),
        3306: ('MySQL', 'CRITICAL', 'Database exposed to internet'),
        3389: ('RDP', 'HIGH', 'Remote desktop'),
        5432: ('PostgreSQL', 'CRITICAL', 'Database exposed to internet'),
        6379: ('Redis', 'CRITICAL', 'Cache/DB often without auth'),
        11211: ('Memcached', 'HIGH', 'Cache server, DDoS amplification'),
        27017: ('MongoDB', 'CRITICAL', 'NoSQL database exposed'),
    }

    # Services that indicate subdomain takeover vulnerability
    TAKEOVER_FINGERPRINTS = {
        'github': {
            'cname': ['github.io', 'github.com'],
            'fingerprint': "There isn't a GitHub Pages site here",
        },
        'heroku': {
            'cname': ['herokuapp.com', 'herokussl.com'],
            'fingerprint': 'No such app',
        },
        'aws_s3': {
            'cname': ['s3.amazonaws.com', 's3-website'],
            'fingerprint': 'NoSuchBucket',
        },
        'shopify': {
            'cname': ['myshopify.com'],
            'fingerprint': 'Sorry, this shop is currently unavailable',
        },
        'tumblr': {
            'cname': ['tumblr.com'],
            'fingerprint': "There's nothing here.",
        },
        'wordpress': {
            'cname': ['wordpress.com'],
            'fingerprint': 'Do you want to register',
        },
        'ghost': {
            'cname': ['ghost.io'],
            'fingerprint': 'The thing you were looking for is no longer here',
        },
        'surge': {
            'cname': ['surge.sh'],
            'fingerprint': 'project not found',
        },
        'bitbucket': {
            'cname': ['bitbucket.io'],
            'fingerprint': 'Repository not found',
        },
        'pantheon': {
            'cname': ['pantheonsite.io'],
            'fingerprint': '404 error unknown site',
        },
    }

    @property
    def name(self) -> str:
        return "Network Scanner"

    def scan(self, **kwargs) -> Dict[str, Any]:
        """
        Run network-level security checks.

        Returns:
            Dictionary with scan results
        """
        self.log.scan("Running network security checks...")
        self.clear_findings()

        # Get hostname from HTTP client
        parsed = urlparse(self.http.base_url)
        self.hostname = parsed.netloc.split(':')[0]

        results = {
            'dns_records': self.check_dns_records(),
            'open_ports': self.check_common_ports(),
            'subdomain_takeover': self.check_subdomain_takeover(),
            'dnssec': self.check_dnssec(),
            'caa_records': self.check_caa_records(),
            'reverse_dns': self.check_reverse_dns(),
            'spf_dmarc': self.check_spf_dmarc(),
            'findings': []
        }

        results['findings'] = self.get_findings()
        return results

    def check_dns_records(self) -> Dict[str, Any]:
        """Check all DNS records for the domain."""
        self.log.scan("Checking DNS records...")

        result = {
            'a': [],
            'aaaa': [],
            'mx': [],
            'ns': [],
            'txt': [],
            'soa': None,
            'cname': None,
        }

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        for rtype in record_types:
            try:
                import subprocess
                output = subprocess.run(
                    ['nslookup', f'-type={rtype}', self.hostname],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                lines = output.stdout.split('\n')
                for line in lines:
                    line_lower = line.lower()

                    if rtype == 'A' and 'address' in line_lower and ':' in line:
                        addr = line.split(':')[-1].strip()
                        if addr and not addr.startswith('::'):
                            result['a'].append(addr)

                    elif rtype == 'AAAA' and 'address' in line_lower:
                        addr = line.split(':')[-1].strip() if '::' not in line else ':'.join(line.split(':')[1:]).strip()
                        if addr:
                            result['aaaa'].append(addr)

                    elif rtype == 'MX' and 'mail exchanger' in line_lower:
                        parts = line.split('=')
                        if len(parts) > 1:
                            result['mx'].append(parts[-1].strip())

                    elif rtype == 'NS' and 'nameserver' in line_lower:
                        parts = line.split('=')
                        if len(parts) > 1:
                            result['ns'].append(parts[-1].strip())

                    elif rtype == 'TXT' and 'text' in line_lower:
                        parts = line.split('=')
                        if len(parts) > 1:
                            result['txt'].append(parts[-1].strip().strip('"'))

                    elif rtype == 'SOA' and 'primary name server' in line_lower:
                        parts = line.split('=')
                        if len(parts) > 1:
                            result['soa'] = parts[-1].strip()

                    elif rtype == 'CNAME' and 'canonical name' in line_lower:
                        parts = line.split('=')
                        if len(parts) > 1:
                            result['cname'] = parts[-1].strip()

            except subprocess.TimeoutExpired:
                self.log.warning(f"DNS lookup for {rtype} timed out")
            except FileNotFoundError:
                pass
            except Exception as e:
                pass

        # Log summary
        self.log.info(f"DNS: {len(result['a'])} A, {len(result['mx'])} MX, {len(result['ns'])} NS, {len(result['txt'])} TXT records")

        return result

    def check_spf_dmarc(self) -> Dict[str, Any]:
        """Check SPF and DMARC records for email security."""
        self.log.scan("Checking SPF/DMARC records...")

        result = {
            'spf': None,
            'spf_valid': False,
            'dmarc': None,
            'dmarc_valid': False,
            'dkim_selector': None,
        }

        try:
            import subprocess

            # Check SPF (TXT record)
            output = subprocess.run(
                ['nslookup', '-type=TXT', self.hostname],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in output.stdout.split('\n'):
                if 'v=spf1' in line.lower():
                    result['spf'] = line.split('=')[-1].strip().strip('"') if '=' in line else line.strip()
                    result['spf_valid'] = True

            # Check DMARC (TXT record at _dmarc subdomain)
            output = subprocess.run(
                ['nslookup', '-type=TXT', f'_dmarc.{self.hostname}'],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in output.stdout.split('\n'):
                if 'v=dmarc1' in line.lower():
                    result['dmarc'] = line.split('=')[-1].strip().strip('"') if '=' in line else line.strip()
                    result['dmarc_valid'] = True

            if not result['spf_valid']:
                self.add_finding(
                    'LOW',
                    'Missing SPF Record',
                    'No SPF record found. Email spoofing may be possible.',
                    'Add an SPF TXT record to prevent email spoofing',
                    evidence='No v=spf1 TXT record found'
                )

            if not result['dmarc_valid']:
                self.add_finding(
                    'LOW',
                    'Missing DMARC Record',
                    'No DMARC record found. Email authentication not enforced.',
                    'Add a DMARC TXT record at _dmarc subdomain',
                    evidence='No v=DMARC1 TXT record found at _dmarc subdomain'
                )

            if result['spf_valid'] and result['dmarc_valid']:
                self.log.success("SPF and DMARC records configured")
            else:
                self.log.warning("Missing SPF or DMARC records")

        except Exception as e:
            self.log.warning(f"SPF/DMARC check failed: {str(e)}")

        return result

    def check_common_ports(self) -> Dict[str, Any]:
        """Quick scan of common vulnerable ports."""
        self.log.scan("Scanning common ports...")

        result = {
            'scanned': [],
            'open': [],
            'filtered': [],
            'vulnerable': []
        }

        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(self.hostname)
        except socket.gaierror:
            self.log.warning(f"Could not resolve hostname: {self.hostname}")
            return result

        result['ip'] = ip

        for port, (service, severity, description) in self.COMMON_PORTS.items():
            result['scanned'].append(port)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                conn_result = sock.connect_ex((ip, port))
                sock.close()

                if conn_result == 0:
                    port_info = {
                        'port': port,
                        'service': service,
                        'severity': severity,
                        'description': description
                    }
                    result['open'].append(port_info)

                    # Report dangerous ports
                    if severity in ['CRITICAL', 'HIGH']:
                        result['vulnerable'].append(port_info)
                        self.add_finding(
                            severity,
                            f'Open Port: {port} ({service})',
                            f'{service} port {port} is open. {description}',
                            f'Close port {port} if not needed, or restrict access via firewall',
                            evidence=f'{ip}:{port} is accessible'
                        )
                        self.log.warning(f"Port {port} ({service}) is open - {severity}")

            except socket.timeout:
                result['filtered'].append(port)
            except Exception:
                continue

        if result['open']:
            self.log.info(f"Found {len(result['open'])} open ports")
        else:
            self.log.success("No common vulnerable ports open")

        return result

    def check_subdomain_takeover(self) -> Dict[str, Any]:
        """Check for subdomain takeover vulnerabilities."""
        self.log.scan("Checking for subdomain takeover...")

        result = {
            'vulnerable': False,
            'cname': None,
            'service': None,
            'details': []
        }

        # Get CNAME record
        try:
            import subprocess
            # Use nslookup or dig to get CNAME
            output = subprocess.run(
                ['nslookup', '-type=CNAME', self.hostname],
                capture_output=True,
                text=True,
                timeout=5
            )

            # Parse CNAME from output
            cname = None
            for line in output.stdout.split('\n'):
                if 'canonical name' in line.lower():
                    parts = line.split('=')
                    if len(parts) > 1:
                        cname = parts[1].strip().rstrip('.')
                        break

            if cname:
                result['cname'] = cname

                # Check if CNAME points to known vulnerable services
                for service, config in self.TAKEOVER_FINGERPRINTS.items():
                    for cname_pattern in config['cname']:
                        if cname_pattern in cname.lower():
                            # Check if the service returns error fingerprint
                            try:
                                response = self.http.get('/')
                                if response and config['fingerprint'] in response.text:
                                    result['vulnerable'] = True
                                    result['service'] = service
                                    result['details'].append({
                                        'cname': cname,
                                        'service': service,
                                        'fingerprint_matched': True
                                    })
                                    self.add_finding(
                                        'HIGH',
                                        'Potential Subdomain Takeover',
                                        f'Domain has CNAME to {cname} ({service}) which shows unclaimed resource fingerprint',
                                        f'Claim the resource on {service} or remove the CNAME record',
                                        evidence=f'CNAME: {cname}, Fingerprint: {config["fingerprint"][:50]}...'
                                    )
                                    self.log.error(f"Subdomain takeover possible via {service}!")
                                    break
                            except Exception:
                                pass

        except subprocess.TimeoutExpired:
            self.log.warning("CNAME lookup timed out")
        except FileNotFoundError:
            # nslookup not available, try with socket
            pass
        except Exception as e:
            self.log.warning(f"Could not check CNAME: {str(e)}")

        if not result['vulnerable']:
            self.log.success("No subdomain takeover vulnerability detected")

        return result

    def check_dnssec(self) -> Dict[str, Any]:
        """Verify DNSSEC configuration."""
        self.log.scan("Checking DNSSEC...")

        result = {
            'enabled': False,
            'validated': False,
            'details': {}
        }

        try:
            import subprocess

            # Check for DNSKEY records
            output = subprocess.run(
                ['nslookup', '-type=DNSKEY', self.hostname],
                capture_output=True,
                text=True,
                timeout=5
            )

            if 'DNSKEY' in output.stdout:
                result['enabled'] = True
                result['details']['dnskey'] = True

            # Check for DS records (indicates delegation is signed)
            output = subprocess.run(
                ['nslookup', '-type=DS', self.hostname],
                capture_output=True,
                text=True,
                timeout=5
            )

            if 'DS' in output.stdout and 'digest' in output.stdout.lower():
                result['validated'] = True
                result['details']['ds'] = True

        except subprocess.TimeoutExpired:
            self.log.warning("DNSSEC lookup timed out")
        except FileNotFoundError:
            self.log.info("nslookup not available for DNSSEC check")
        except Exception as e:
            self.log.warning(f"DNSSEC check failed: {str(e)}")

        if not result['enabled']:
            self.add_finding(
                'LOW',
                'DNSSEC Not Enabled',
                'Domain does not have DNSSEC configured, making it vulnerable to DNS spoofing',
                'Enable DNSSEC at your domain registrar to protect against DNS attacks',
                evidence='No DNSKEY records found'
            )
            self.log.info("DNSSEC not enabled")
        else:
            self.log.success("DNSSEC is enabled")

        return result

    def check_caa_records(self) -> Dict[str, Any]:
        """Check CAA DNS records for certificate control."""
        self.log.scan("Checking CAA records...")

        result = {
            'has_caa': False,
            'records': [],
            'issuers': []
        }

        try:
            import subprocess

            output = subprocess.run(
                ['nslookup', '-type=CAA', self.hostname],
                capture_output=True,
                text=True,
                timeout=5
            )

            # Parse CAA records
            for line in output.stdout.split('\n'):
                line_lower = line.lower()
                if 'issue' in line_lower or 'issuewild' in line_lower or 'iodef' in line_lower:
                    result['has_caa'] = True
                    result['records'].append(line.strip())

                    # Extract issuer CA
                    if 'issue' in line_lower:
                        parts = line.split('"')
                        if len(parts) > 1:
                            result['issuers'].append(parts[1])

        except subprocess.TimeoutExpired:
            self.log.warning("CAA lookup timed out")
        except FileNotFoundError:
            self.log.info("nslookup not available for CAA check")
        except Exception as e:
            self.log.warning(f"CAA check failed: {str(e)}")

        if not result['has_caa']:
            self.add_finding(
                'LOW',
                'No CAA Records',
                'Domain has no CAA records, any CA can issue certificates for this domain',
                'Add CAA DNS records to restrict which CAs can issue certificates',
                evidence='No CAA records found'
            )
            self.log.info("No CAA records found")
        else:
            self.log.success(f"CAA records found: {len(result['issuers'])} issuer(s)")

        return result

    def check_reverse_dns(self) -> Dict[str, Any]:
        """Check reverse DNS configuration."""
        self.log.scan("Checking reverse DNS...")

        result = {
            'ip': None,
            'ptr': None,
            'matches': False
        }

        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(self.hostname)
            result['ip'] = ip

            # Get PTR record
            ptr = socket.gethostbyaddr(ip)[0]
            result['ptr'] = ptr

            # Check if forward lookup matches
            result['matches'] = self.hostname.lower() in ptr.lower() or ptr.lower() in self.hostname.lower()

            if result['matches']:
                self.log.success(f"Reverse DNS configured: {ptr}")
            else:
                self.log.info(f"Reverse DNS: {ptr} (different from {self.hostname})")

        except socket.herror:
            self.log.info("No reverse DNS record found")
        except socket.gaierror:
            self.log.warning(f"Could not resolve: {self.hostname}")
        except Exception as e:
            self.log.warning(f"Reverse DNS check failed: {str(e)}")

        return result
