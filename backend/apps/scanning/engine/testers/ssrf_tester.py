"""
SSRFTester — Tests for Server-Side Request Forgery.
OWASP A10:2021 — Server-Side Request Forgery (SSRF).
"""
import re
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

SSRF_PAYLOADS = [
    'http://127.0.0.1',
    'http://localhost',
    'http://0.0.0.0',
    'http://[::1]',
    'http://169.254.169.254/latest/meta-data/',   # AWS metadata
    'http://metadata.google.internal/',             # GCP metadata
    'http://169.254.169.254/metadata/v1/',          # Azure / DigitalOcean
    'http://127.0.0.1:22',                          # SSH port
    'http://127.0.0.1:3306',                        # MySQL port
    'http://127.0.0.1:6379',                        # Redis port
]

URL_PARAM_NAMES = [
    'url', 'uri', 'link', 'src', 'source', 'href', 'redirect',
    'target', 'dest', 'destination', 'next', 'return', 'return_url',
    'callback', 'proxy', 'fetch', 'load', 'file', 'path', 'page',
    'image', 'img', 'feed', 'resource',
]


class SSRFTester(BaseTester):
    """Test for Server-Side Request Forgery vulnerabilities."""

    TESTER_NAME = 'SSRF'

    def test(self, page, depth: str = 'medium') -> list:
        vulnerabilities = []
        payloads = SSRF_PAYLOADS[:4] if depth == 'shallow' else SSRF_PAYLOADS

        # Test URL parameters that might trigger server-side requests
        for param_name in page.parameters:
            if not self._is_url_param(param_name):
                continue

            vuln = self._test_ssrf_param(page.url, param_name, payloads)
            if vuln:
                vulnerabilities.append(vuln)

        # Test form inputs with URL-like names
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button'):
                    continue
                if not self._is_url_param(inp.name or ''):
                    continue

                vuln = self._test_ssrf_form(form, inp, payloads, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # Check for open redirect (related to SSRF)
        if depth in ('medium', 'deep'):
            vuln = self._test_open_redirect(page)
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_url_param(self, param_name):
        """Check if a parameter name suggests it accepts URLs."""
        return param_name.lower() in URL_PARAM_NAMES

    def _test_ssrf_param(self, url, param_name, payloads):
        """Test a URL parameter for SSRF."""
        for payload in payloads:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = payload

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), ''
            ))

            response = self._make_request('GET', test_url)
            if response and self._is_ssrf_success(response, payload):
                return self._build_vuln(
                    name=f'SSRF via Parameter: {param_name}',
                    severity='critical' if '169.254' in payload else 'high',
                    category='Server-Side Request Forgery',
                    description=f'The parameter "{param_name}" can be used to make server-side requests '
                               f'to internal resources.',
                    impact='Attackers can access internal services, cloud metadata endpoints, '
                          'and bypass network firewalls. In cloud environments, this can lead '
                          'to credential theft via metadata services.',
                    remediation='Validate and sanitize all URLs. Use an allowlist of permitted domains. '
                               'Block requests to internal/private IP ranges. '
                               'Disable unnecessary URL schemes (file://, gopher://, dict://).',
                    cwe='CWE-918',
                    cvss=9.1 if '169.254' in payload else 7.5,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\n'
                            f'Server-side request to internal resource detected.',
                )
        return None

    def _test_ssrf_form(self, form, inp, payloads, page_url):
        """Test a form input for SSRF."""
        for payload in payloads[:3]:  # Limit payloads for forms
            data = {}
            for form_inp in form.inputs:
                if form_inp.name == inp.name:
                    data[form_inp.name] = payload
                else:
                    data[form_inp.name] = form_inp.value or 'test'

            target_url = form.action or page_url
            method = form.method.upper()

            if method == 'POST':
                response = self._make_request('POST', target_url, data=data)
            else:
                response = self._make_request('GET', target_url, params=data)

            if response and self._is_ssrf_success(response, payload):
                return self._build_vuln(
                    name=f'SSRF via Form Field: {inp.name}',
                    severity='high',
                    category='Server-Side Request Forgery',
                    description=f'Form field "{inp.name}" can trigger server-side requests.',
                    impact='Internal services and cloud metadata may be accessible via this field.',
                    remediation='Validate URLs against an allowlist. Block private IP ranges.',
                    cwe='CWE-918',
                    cvss=7.5,
                    affected_url=target_url,
                    evidence=f'Form field: {inp.name}\nPayload: {payload}',
                )
        return None

    def _test_open_redirect(self, page):
        """Test for open redirect vulnerabilities."""
        redirect_params = ['redirect', 'next', 'url', 'return', 'return_url',
                           'dest', 'destination', 'redir', 'continue']

        for param_name in page.parameters:
            if param_name.lower() not in redirect_params:
                continue

            payload = 'https://evil-attacker.com'
            parsed = urlparse(page.url)
            params = parse_qs(parsed.query)
            params[param_name] = payload

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), ''
            ))

            response = self._make_request('GET', test_url, allow_redirects=False)
            if response and response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location', '')
                if 'evil-attacker.com' in location:
                    return self._build_vuln(
                        name=f'Open Redirect: {param_name}',
                        severity='medium',
                        category='Server-Side Request Forgery',
                        description=f'Parameter "{param_name}" allows redirecting users to arbitrary external sites.',
                        impact='Attackers can craft links that redirect victims to phishing pages, '
                              'abusing the trusted domain reputation.',
                        remediation='Validate redirect URLs against a whitelist of allowed domains. '
                                   'Use relative URLs for redirects. '
                                   'Show a warning page before redirecting to external sites.',
                        cwe='CWE-601',
                        cvss=4.7,
                        affected_url=page.url,
                        evidence=f'Parameter: {param_name}\nRedirected to: {location}',
                    )
        return None

    def _is_ssrf_success(self, response, payload):
        """Determine if SSRF was successful based on response."""
        if response.status_code == 200:
            body = response.text.lower()
            # Check for internal service responses
            if '169.254' in payload:
                # Cloud metadata indicators
                metadata_indicators = [
                    'ami-id', 'instance-id', 'security-credentials',
                    'computeMetadata', 'instance/hostname',
                ]
                if any(ind.lower() in body for ind in metadata_indicators):
                    return True
            # Check for internal service banners
            internal_indicators = [
                'openssh', 'mysql', 'redis', 'apache',
                'nginx', 'iis', 'tomcat',
            ]
            if any(ind in body for ind in internal_indicators):
                return True
        # Check for timing differences (SSRF might cause delays)
        return False
