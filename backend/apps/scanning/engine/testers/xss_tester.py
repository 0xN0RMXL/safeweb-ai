"""
XSSTester — Tests for Cross-Site Scripting vulnerabilities.
OWASP A03:2021 — Injection (XSS).
"""
import re
import logging
import html
from urllib.parse import quote
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<body onload=alert("XSS")>',
    '<details open ontoggle=alert("XSS")>',
    '{{7*7}}',  # Template injection check
    '${7*7}',   # Template injection check
    '<iframe src="javascript:alert(1)">',
]

# Unique canary to detect reflection
CANARY = 'swai9x7z'


class XSSTester(BaseTester):
    """Test for reflected and DOM-based XSS vulnerabilities."""

    TESTER_NAME = 'XSS'

    def test(self, page, depth: str = 'medium') -> list:
        vulnerabilities = []
        payloads = XSS_PAYLOADS[:4] if depth == 'shallow' else XSS_PAYLOADS

        # Test URL parameters
        for param_name in page.parameters:
            vuln = self._test_reflected_xss(page.url, param_name, payloads)
            if vuln:
                vulnerabilities.append(vuln)

        # Test form inputs
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button', 'file'):
                    continue
                vuln = self._test_form_xss(form, inp, payloads, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

        # Check for DOM XSS indicators in page source
        dom_vuln = self._check_dom_xss(page)
        if dom_vuln:
            vulnerabilities.append(dom_vuln)

        return vulnerabilities

    def _test_reflected_xss(self, url, param_name, payloads):
        """Test URL parameter for reflected XSS."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        for payload in payloads:
            tagged_payload = f'{CANARY}{payload}'
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = tagged_payload

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(params, doseq=True), ''
            ))

            response = self._make_request('GET', test_url)
            if response and self._is_reflected(response.text, payload):
                return self._build_vuln(
                    name=f'Reflected XSS in Parameter: {param_name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'The parameter "{param_name}" reflects user input without proper encoding, '
                               f'allowing injection of malicious scripts.',
                    impact='An attacker can execute arbitrary JavaScript in a victim\'s browser, '
                          'stealing session cookies, credentials, or performing actions on behalf of the user.',
                    remediation='Encode all user input before rendering in HTML. Use context-aware output encoding. '
                               'Implement Content Security Policy (CSP) headers. '
                               'In templates: use {{variable}} with auto-escaping enabled.',
                    cwe='CWE-79',
                    cvss=6.1,
                    affected_url=url,
                    evidence=f'Parameter: {param_name}\nPayload: {payload}\nPayload was reflected unescaped in response.',
                )
        return None

    def _test_form_xss(self, form, inp, payloads, page_url):
        """Test form input for reflected XSS."""
        for payload in payloads:
            data = {}
            for form_inp in form.inputs:
                if form_inp.name == inp.name:
                    data[form_inp.name] = f'{CANARY}{payload}'
                else:
                    data[form_inp.name] = form_inp.value or 'test'

            target_url = form.action or page_url
            method = form.method.upper()

            if method == 'POST':
                response = self._make_request('POST', target_url, data=data)
            else:
                response = self._make_request('GET', target_url, params=data)

            if response and self._is_reflected(response.text, payload):
                return self._build_vuln(
                    name=f'Reflected XSS in Form Field: {inp.name}',
                    severity='high',
                    category='Cross-Site Scripting',
                    description=f'The form field "{inp.name}" reflects input without encoding.',
                    impact='Attackers can inject scripts that steal user sessions, redirect users, or modify page content.',
                    remediation='Apply output encoding. Use DOMPurify for client-side sanitization. '
                               'Set Content-Security-Policy header to restrict inline scripts.',
                    cwe='CWE-79',
                    cvss=6.1,
                    affected_url=target_url,
                    evidence=f'Form: {form.method} {target_url}\nField: {inp.name}\nPayload: {payload}',
                )
        return None

    def _is_reflected(self, body, payload):
        """Check if XSS payload is reflected unescaped in response."""
        if not body:
            return False
        # Check direct reflection (unescaped)
        if payload in body:
            # Make sure it's not just the HTML-encoded version
            encoded = html.escape(payload)
            if encoded not in body or payload in body.replace(encoded, ''):
                return True
        # Check template injection
        if payload == '{{7*7}}' and '49' in body:
            return True
        if payload == '${7*7}' and '49' in body:
            return True
        return False

    def _check_dom_xss(self, page):
        """Check for potential DOM-based XSS sinks in JavaScript."""
        dangerous_patterns = [
            r'document\.write\s*\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'eval\s*\(',
            r'document\.location\s*=',
            r'window\.location\s*=',
            r'document\.URL',
            r'document\.referrer',
        ]

        body = page.body
        found_sinks = []
        for pattern in dangerous_patterns:
            if re.search(pattern, body):
                found_sinks.append(pattern.replace('\\s*\\(', '()').replace('\\', ''))

        if found_sinks:
            return self._build_vuln(
                name='Potential DOM-based XSS Sinks Detected',
                severity='medium',
                category='Cross-Site Scripting',
                description=f'The page contains JavaScript functions known as DOM XSS sinks: {", ".join(found_sinks[:5])}.',
                impact='If user-controlled data flows into these sinks, attackers may execute arbitrary JavaScript.',
                remediation='Avoid using dangerous DOM manipulation methods. Use textContent instead of innerHTML. '
                           'Sanitize all user input with DOMPurify before inserting into the DOM.',
                cwe='CWE-79',
                cvss=5.4,
                affected_url=page.url,
                evidence=f'DOM sinks found: {", ".join(found_sinks[:5])}',
            )
        return None
