"""
CSRFTester — Tests for Cross-Site Request Forgery vulnerabilities.
OWASP A01:2021 — Broken Access Control.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)


class CSRFTester(BaseTester):
    """Test for missing CSRF protection on state-changing forms."""

    TESTER_NAME = 'CSRF'

    CSRF_TOKEN_NAMES = [
        'csrf', 'csrftoken', 'csrf_token', '_csrf', 'authenticity_token',
        'xsrf', 'xsrf_token', '_xsrf', '__RequestVerificationToken',
        'csrfmiddlewaretoken', 'antiforgery',
    ]

    def test(self, page, depth: str = 'medium') -> list:
        vulnerabilities = []

        for form in page.forms:
            if form.method.upper() != 'POST':
                continue

            has_csrf = False
            for inp in form.inputs:
                if inp.input_type == 'hidden' and any(
                    tok in (inp.name or '').lower() for tok in self.CSRF_TOKEN_NAMES
                ):
                    has_csrf = True
                    break

            if not has_csrf:
                # Also check for CSRF in meta tags / headers
                has_csrf = self._check_meta_csrf(page.body)

            if not has_csrf:
                vulnerabilities.append(self._build_vuln(
                    name='Missing CSRF Token on Form',
                    severity='medium',
                    category='Cross-Site Request Forgery',
                    description=f'A POST form at {form.action or page.url} does not include a CSRF token, '
                               f'making it vulnerable to cross-site request forgery attacks.',
                    impact='An attacker can craft a malicious page that submits this form on behalf of '
                          'an authenticated user, performing unauthorized actions like changing passwords, '
                          'transferring funds, or modifying account settings.',
                    remediation='Include a unique, unpredictable CSRF token in every state-changing form. '
                               'Validate the token server-side on each request. '
                               'Use the SameSite cookie attribute as an additional defense.',
                    cwe='CWE-352',
                    cvss=4.3,
                    affected_url=form.action or page.url,
                    evidence=f'POST form found without CSRF token.\nAction: {form.action}\n'
                            f'Fields: {", ".join(i.name for i in form.inputs if i.name)}',
                ))

        # Check SameSite cookie attribute (additional CSRF defense)
        if depth in ('medium', 'deep'):
            response = self._make_request('GET', page.url)
            if response:
                for cookie_name, cookie in response.cookies.items():
                    same_site = getattr(cookie, 'same_site', None)
                    if same_site is None or same_site.lower() == 'none':
                        vulnerabilities.append(self._build_vuln(
                            name=f'Cookie Missing SameSite Attribute: {cookie_name}',
                            severity='low',
                            category='Cross-Site Request Forgery',
                            description=f'Cookie "{cookie_name}" is missing the SameSite attribute or has it set to None.',
                            impact='Without SameSite, cookies are sent with cross-origin requests, '
                                  'making CSRF attacks easier.',
                            remediation='Set the SameSite attribute to "Lax" or "Strict" on all cookies.',
                            cwe='CWE-1275',
                            cvss=3.1,
                            affected_url=page.url,
                            evidence=f'Cookie: {cookie_name}\nSameSite: {same_site or "not set"}',
                        ))
                        break  # Report once

        return vulnerabilities

    def _check_meta_csrf(self, body):
        """Check for CSRF token in meta tags (common in SPAs)."""
        pattern = r'<meta\s+[^>]*name=["\']csrf[^"\']*["\'][^>]*>'
        return bool(re.search(pattern, body, re.IGNORECASE))
