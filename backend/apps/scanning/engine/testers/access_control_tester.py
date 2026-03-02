"""
AccessControlTester — Tests for broken access control.
OWASP A01:2021 — Broken Access Control.
"""
import re
import logging
from urllib.parse import urlparse, urljoin
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
]

FORCED_BROWSING_PATHS = [
    '/admin',
    '/admin/dashboard',
    '/api/admin',
    '/api/users',
    '/api/v1/users',
    '/internal',
    '/debug',
    '/config',
    '/backup',
    '/logs',
    '/test',
    '/staging',
]


class AccessControlTester(BaseTester):
    """Test for broken access control vulnerabilities."""

    TESTER_NAME = 'Access Control'

    def test(self, page, depth: str = 'medium') -> list:
        vulnerabilities = []

        # Test IDOR in URL parameters
        vulns = self._test_idor(page)
        vulnerabilities.extend(vulns)

        # Test directory traversal
        vulns = self._test_directory_traversal(page)
        vulnerabilities.extend(vulns)

        # Test forced browsing
        if depth in ('medium', 'deep'):
            paths = FORCED_BROWSING_PATHS[:6] if depth == 'medium' else FORCED_BROWSING_PATHS
            vulns = self._test_forced_browsing(page.url, paths)
            vulnerabilities.extend(vulns)

        # Check for missing function-level access control
        vuln = self._test_method_override(page.url)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _test_idor(self, page):
        """Test for Insecure Direct Object References."""
        vulnerabilities = []

        for param_name, param_value in page.parameters.items():
            # Check if parameter looks like an ID
            if not self._is_id_param(param_name, param_value):
                continue

            # Try modifying the ID
            test_ids = self._generate_test_ids(param_value)
            for test_id in test_ids:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(page.url)
                params = parse_qs(parsed.query)
                params[param_name] = test_id

                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), ''
                ))

                response = self._make_request('GET', test_url)
                if response and response.status_code == 200:
                    # Check if we got different content (potential IDOR)
                    original = self._make_request('GET', page.url)
                    if original and response.text != original.text and len(response.text) > 100:
                        vulnerabilities.append(self._build_vuln(
                            name=f'Potential IDOR: {param_name}',
                            severity='high',
                            category='Broken Access Control',
                            description=f'Parameter "{param_name}" may be vulnerable to Insecure Direct Object '
                                       f'Reference — different IDs return different content without authorization checks.',
                            impact='Attackers can access other users\' data by manipulating object references.',
                            remediation='Implement proper authorization checks for every data access. '
                                       'Use indirect object references or UUIDs instead of sequential IDs.',
                            cwe='CWE-639',
                            cvss=6.5,
                            affected_url=page.url,
                            evidence=f'Parameter: {param_name}\nOriginal: {param_value}\nTest: {test_id}\n'
                                    f'Both returned 200 with different content.',
                        ))
                        break

        return vulnerabilities

    def _test_directory_traversal(self, page):
        """Test for path traversal vulnerabilities."""
        vulnerabilities = []

        for param_name, param_value in page.parameters.items():
            # Only test params that look like file paths
            if not any(k in param_name.lower() for k in ('file', 'path', 'page', 'doc', 'template', 'include', 'dir')):
                continue

            for payload in TRAVERSAL_PAYLOADS[:3]:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                parsed = urlparse(page.url)
                params = parse_qs(parsed.query)
                params[param_name] = payload

                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), ''
                ))

                response = self._make_request('GET', test_url)
                if response and response.status_code == 200:
                    # Check for path traversal success indicators
                    indicators = ['root:', 'bin/bash', '[extensions]', '[fonts]',
                                  'for 16-bit app support']
                    if any(ind in response.text for ind in indicators):
                        vulnerabilities.append(self._build_vuln(
                            name=f'Path Traversal: {param_name}',
                            severity='critical',
                            category='Broken Access Control',
                            description=f'Parameter "{param_name}" is vulnerable to directory traversal, '
                                       f'allowing access to files outside the web root.',
                            impact='Attackers can read arbitrary files on the server, including '
                                  'configuration files, password files, and application source code.',
                            remediation='Validate and sanitize file paths. Use a whitelist of allowed files. '
                                       'Canonicalize paths and verify they resolve within the intended directory.',
                            cwe='CWE-22',
                            cvss=9.1,
                            affected_url=page.url,
                            evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                                    f'System file content detected in response.',
                        ))
                        return vulnerabilities  # One finding is enough

        return vulnerabilities

    def _test_forced_browsing(self, url, paths):
        """Test for access to restricted resources without authentication."""
        parsed = urlparse(url)
        base = f'{parsed.scheme}://{parsed.netloc}'
        vulnerabilities = []
        found_count = 0

        for path in paths:
            test_url = urljoin(base, path)
            response = self._make_request('GET', test_url)
            if not response:
                continue

            if response.status_code == 200 and len(response.text) > 200:
                # Check if it looks like an admin/restricted page
                body = response.text.lower()
                admin_indicators = [
                    'dashboard', 'admin', 'users', 'settings',
                    'configuration', 'manage', 'control panel',
                ]
                if any(ind in body for ind in admin_indicators):
                    found_count += 1
                    if found_count <= 3:  # Limit findings
                        vulnerabilities.append(self._build_vuln(
                            name=f'Unrestricted Access: {path}',
                            severity='high',
                            category='Broken Access Control',
                            description=f'The restricted path {path} is accessible without authentication.',
                            impact='Unauthorized users can access administrative functions or sensitive data.',
                            remediation='Implement authentication and authorization checks for all restricted endpoints. '
                                       'Use role-based access control (RBAC).',
                            cwe='CWE-425',
                            cvss=7.5,
                            affected_url=test_url,
                            evidence=f'HTTP 200 for {path} — admin/management content detected.',
                        ))

        return vulnerabilities

    def _test_method_override(self, url):
        """Test for HTTP method override bypasses."""
        # Try X-HTTP-Method-Override to bypass restrictions
        headers = {'X-HTTP-Method-Override': 'DELETE'}
        response = self._make_request('POST', url, headers=headers)
        if response and response.status_code in (200, 204):
            headers2 = {'X-HTTP-Method-Override': 'PUT'}
            response2 = self._make_request('POST', url, headers=headers2)
            if response2 and response2.status_code in (200, 204):
                return self._build_vuln(
                    name='HTTP Method Override Accepted',
                    severity='medium',
                    category='Broken Access Control',
                    description='The server processes X-HTTP-Method-Override headers, '
                               'potentially bypassing method-based access controls.',
                    impact='Attackers may use method override to access restricted operations.',
                    remediation='Disable HTTP method override in production. '
                               'Apply access controls based on the actual HTTP method.',
                    cwe='CWE-650',
                    cvss=5.3,
                    affected_url=url,
                    evidence='Server accepted X-HTTP-Method-Override header.',
                )
        return None

    def _is_id_param(self, name, value):
        """Check if a parameter looks like an object ID."""
        if any(k in name.lower() for k in ('id', 'uid', 'user', 'account', 'order', 'doc')):
            return True
        # Check if value is numeric
        try:
            int(value)
            return True
        except (ValueError, TypeError):
            pass
        return False

    def _generate_test_ids(self, original_value):
        """Generate test IDs based on the original value."""
        test_ids = []
        try:
            num = int(original_value)
            test_ids.extend([str(num + 1), str(num - 1), '1', '0'])
        except (ValueError, TypeError):
            test_ids.extend(['1', '2', 'admin'])
        return test_ids[:2]  # Limit to 2 tests
