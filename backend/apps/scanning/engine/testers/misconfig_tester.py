"""
MisconfigTester — Tests for security misconfigurations.
OWASP A05:2021 — Security Misconfiguration.
"""
import re
import logging
from urllib.parse import urljoin
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = [
    '/.env',
    '/.git/config',
    '/.git/HEAD',
    '/wp-admin/',
    '/admin/',
    '/administrator/',
    '/phpmyadmin/',
    '/server-status',
    '/server-info',
    '/elmah.axd',
    '/.htaccess',
    '/.htpasswd',
    '/web.config',
    '/crossdomain.xml',
    '/info.php',
    '/phpinfo.php',
    '/debug',
    '/__debug__/',
    '/actuator',
    '/actuator/health',
    '/api/swagger.json',
    '/swagger-ui.html',
]

DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT']


class MisconfigTester(BaseTester):
    """Test for server and application misconfigurations."""

    TESTER_NAME = 'Misconfiguration'

    def test(self, page, depth: str = 'medium') -> list:
        vulnerabilities = []

        # Test directory listing
        vuln = self._test_directory_listing(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Test dangerous HTTP methods
        vuln = self._test_http_methods(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        # Test exposed sensitive files/paths
        if depth in ('medium', 'deep'):
            paths = SENSITIVE_PATHS[:10] if depth == 'medium' else SENSITIVE_PATHS
            vulns = self._test_sensitive_paths(page.url, paths)
            vulnerabilities.extend(vulns)

        # Test verbose error pages
        if depth in ('medium', 'deep'):
            vuln = self._test_verbose_errors(page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # Test CORS misconfiguration
        vuln = self._test_cors(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_directory_listing(self, url):
        """Check if directory listing is enabled."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        # Try the root and a common directory
        for path in ['/', '/images/', '/css/', '/js/', '/assets/', '/static/']:
            test_url = f'{parsed.scheme}://{parsed.netloc}{path}'
            response = self._make_request('GET', test_url)
            if response and response.status_code == 200:
                indicators = [
                    '<title>Index of', 'Directory listing for',
                    '<title>Directory Listing', 'Parent Directory',
                    '[To Parent Directory]',
                ]
                if any(ind in response.text for ind in indicators):
                    return self._build_vuln(
                        name='Directory Listing Enabled',
                        severity='medium',
                        category='Security Misconfiguration',
                        description=f'Directory listing is enabled at {test_url}, exposing file structure.',
                        impact='Attackers can view all files in the directory, potentially discovering '
                              'sensitive files, backup files, or configuration data.',
                        remediation='Disable directory listing in web server configuration. '
                                   'Apache: Options -Indexes. Nginx: autoindex off.',
                        cwe='CWE-548',
                        cvss=5.3,
                        affected_url=test_url,
                        evidence='Directory listing page detected.',
                    )
        return None

    def _test_http_methods(self, url):
        """Check for dangerous HTTP methods."""
        response = self._make_request('OPTIONS', url)
        if not response:
            return None

        allow = response.headers.get('Allow', '')
        enabled = [m for m in DANGEROUS_METHODS if m in allow.upper()]

        # Also test TRACE directly
        trace_resp = self._make_request('TRACE', url)
        if trace_resp and trace_resp.status_code == 200:
            if 'TRACE' not in enabled:
                enabled.append('TRACE')

        if enabled:
            return self._build_vuln(
                name='Dangerous HTTP Methods Enabled',
                severity='medium',
                category='Security Misconfiguration',
                description=f'The server allows dangerous HTTP methods: {", ".join(enabled)}.',
                impact='TRACE can be used for Cross-Site Tracing (XST) attacks. '
                      'PUT/DELETE may allow unauthorized file manipulation.',
                remediation='Disable unnecessary HTTP methods. Only allow GET, POST, HEAD as needed.',
                cwe='CWE-749',
                cvss=4.3,
                affected_url=url,
                evidence=f'Enabled methods: {allow or ", ".join(enabled)}',
            )
        return None

    def _test_sensitive_paths(self, url, paths):
        """Check for exposed sensitive files and admin interfaces."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = f'{parsed.scheme}://{parsed.netloc}'
        vulnerabilities = []

        for path in paths:
            test_url = urljoin(base, path)
            response = self._make_request('GET', test_url)
            if not response:
                continue

            if response.status_code == 200:
                # Verify it's not a generic 200 (soft 404)
                if len(response.text) < 50:
                    continue

                severity = 'high'
                cwe = 'CWE-538'
                cvss = 7.5

                if '.git' in path:
                    severity = 'critical'
                    cvss = 9.1
                    desc = 'Git repository exposed'
                elif '.env' in path:
                    severity = 'critical'
                    cvss = 9.1
                    desc = 'Environment file exposed (may contain secrets)'
                elif 'phpinfo' in path or 'info.php' in path:
                    severity = 'medium'
                    cvss = 5.3
                    desc = 'PHP info page exposed'
                elif 'admin' in path.lower():
                    severity = 'medium'
                    cvss = 5.3
                    desc = 'Admin interface accessible'
                elif 'swagger' in path.lower() or 'actuator' in path.lower():
                    severity = 'medium'
                    cvss = 5.3
                    desc = 'API documentation/management endpoint exposed'
                elif 'debug' in path.lower():
                    severity = 'high'
                    cvss = 7.5
                    desc = 'Debug interface accessible'
                else:
                    desc = f'Sensitive file accessible: {path}'

                vulnerabilities.append(self._build_vuln(
                    name=f'Sensitive Path Exposed: {path}',
                    severity=severity,
                    category='Security Misconfiguration',
                    description=f'{desc}. The path {path} is publicly accessible.',
                    impact='Exposed files may reveal configuration, credentials, source code, '
                          'or internal application details.',
                    remediation='Restrict access to sensitive files and directories. '
                               'Remove unnecessary files from production. '
                               'Use web server rules to deny access to dot files.',
                    cwe=cwe,
                    cvss=cvss,
                    affected_url=test_url,
                    evidence=f'HTTP {response.status_code} response for {path} ({len(response.text)} bytes)',
                ))

        return vulnerabilities

    def _test_verbose_errors(self, url):
        """Test for verbose error pages that reveal stack traces."""
        # Trigger a 404 with unusual characters
        test_url = url.rstrip('/') + '/nonexistent_page_SafeWebAI_test_7291'
        response = self._make_request('GET', test_url)
        if not response:
            return None

        error_indicators = [
            'Traceback (most recent call last)',
            'Stack Trace:',
            'at System.',
            'java.lang.',
            'PHP Fatal error',
            'PHP Warning',
            'SQLSTATE[',
            'Microsoft OLE DB',
            'Django Version:',
            'DEBUG = True',
            'You\'re seeing this error because',
            'Laravel',
        ]

        for indicator in error_indicators:
            if indicator in response.text:
                return self._build_vuln(
                    name='Verbose Error Messages',
                    severity='medium',
                    category='Security Misconfiguration',
                    description='The application displays detailed error messages including stack traces '
                               'or framework information.',
                    impact='Debug information helps attackers understand the technology stack, '
                          'file structure, and potential attack vectors.',
                    remediation='Disable debug mode in production. Configure custom error pages. '
                               'Log errors server-side without exposing details to users.',
                    cwe='CWE-209',
                    cvss=5.3,
                    affected_url=test_url,
                    evidence=f'Error indicator found: {indicator}',
                )
        return None

    def _test_cors(self, url):
        """Test for overly permissive CORS configuration."""
        headers = {'Origin': 'https://evil-attacker.com'}
        response = self._make_request('GET', url, headers=headers)
        if not response:
            return None

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')

        if acao == '*':
            return self._build_vuln(
                name='Overly Permissive CORS Policy',
                severity='medium',
                category='Security Misconfiguration',
                description='The Access-Control-Allow-Origin header is set to "*", allowing any origin.',
                impact='Any website can make cross-origin requests to this application, '
                      'potentially accessing sensitive data.',
                remediation='Restrict CORS to specific trusted origins. '
                           'Do not use wildcard (*) with credentials.',
                cwe='CWE-942',
                cvss=5.3,
                affected_url=url,
                evidence=f'Access-Control-Allow-Origin: {acao}',
            )

        if 'evil-attacker.com' in acao and acac.lower() == 'true':
            return self._build_vuln(
                name='CORS Origin Reflection with Credentials',
                severity='high',
                category='Security Misconfiguration',
                description='The server reflects the Origin header in Access-Control-Allow-Origin '
                           'and allows credentials, enabling cross-origin attacks.',
                impact='An attacker can steal authenticated user data from any origin.',
                remediation='Validate the Origin header against a whitelist. '
                           'Never reflect arbitrary origins with credentials enabled.',
                cwe='CWE-942',
                cvss=7.5,
                affected_url=url,
                evidence=f'ACAO: {acao}, ACAC: {acac}',
            )
        return None
