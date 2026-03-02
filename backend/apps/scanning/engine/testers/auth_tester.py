"""
AuthTester — Tests for authentication and session management issues.
OWASP A07:2021 — Identification and Authentication Failures.
"""
import re
import logging
from urllib.parse import urlparse
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('root', 'root'),
    ('test', 'test'),
    ('user', 'user'),
    ('admin', 'admin123'),
]


class AuthTester(BaseTester):
    """Test for authentication and session management weaknesses."""

    TESTER_NAME = 'Authentication'

    def test(self, page, depth: str = 'medium') -> list:
        vulnerabilities = []

        # Check for login forms
        login_form = self._find_login_form(page)
        if login_form:
            # Test default credentials
            if depth in ('medium', 'deep'):
                vuln = self._test_default_creds(login_form, page.url)
                if vuln:
                    vulnerabilities.append(vuln)

            # Check for brute force protection
            vuln = self._test_brute_force_protection(login_form, page.url)
            if vuln:
                vulnerabilities.append(vuln)

            # Check for account enumeration
            vuln = self._test_account_enumeration(login_form, page.url)
            if vuln:
                vulnerabilities.append(vuln)

        # Check for login over HTTP
        if page.url.startswith('http://'):
            vuln = self._check_http_login(page)
            if vuln:
                vulnerabilities.append(vuln)

        # Check password autocomplete
        vuln = self._check_password_autocomplete(page)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _find_login_form(self, page):
        """Identify a login form on the page."""
        for form in page.forms:
            has_password = False
            has_username = False
            for inp in form.inputs:
                if inp.input_type == 'password':
                    has_password = True
                if inp.input_type in ('text', 'email') or (
                    inp.name and any(k in inp.name.lower() for k in ('user', 'email', 'login', 'name'))
                ):
                    has_username = True
            if has_password and has_username:
                return form
        return None

    def _test_default_creds(self, form, page_url):
        """Test for default/common credentials."""
        username_field = None
        password_field = None

        for inp in form.inputs:
            if inp.input_type == 'password':
                password_field = inp.name
            elif inp.input_type in ('text', 'email') or (
                inp.name and any(k in inp.name.lower() for k in ('user', 'email', 'login'))
            ):
                username_field = inp.name

        if not username_field or not password_field:
            return None

        target_url = form.action or page_url

        for username, password in DEFAULT_CREDENTIALS[:3]:  # Limit attempts
            data = {username_field: username, password_field: password}
            for inp in form.inputs:
                if inp.name not in data:
                    data[inp.name] = inp.value or ''

            response = self._make_request('POST', target_url, data=data, allow_redirects=False)
            if response and self._is_login_success(response):
                return self._build_vuln(
                    name='Default Credentials Accepted',
                    severity='critical',
                    category='Authentication',
                    description=f'The application accepts default credentials ({username}:{password}).',
                    impact='An attacker can gain full access to the application using widely known credentials.',
                    remediation='Remove default credentials. Force password change on first login. '
                               'Implement password complexity requirements.',
                    cwe='CWE-798',
                    cvss=9.8,
                    affected_url=target_url,
                    evidence=f'Login form accepted credentials: {username}:{"*" * len(password)}',
                )
        return None

    def _test_brute_force_protection(self, form, page_url):
        """Test if the application has brute force protection."""
        username_field = None
        password_field = None

        for inp in form.inputs:
            if inp.input_type == 'password':
                password_field = inp.name
            elif inp.input_type in ('text', 'email') or (
                inp.name and any(k in inp.name.lower() for k in ('user', 'email', 'login'))
            ):
                username_field = inp.name

        if not username_field or not password_field:
            return None

        target_url = form.action or page_url
        blocked = False

        # Try 6 rapid invalid logins
        for i in range(6):
            data = {username_field: 'testuser', password_field: f'wrongpass{i}'}
            for inp in form.inputs:
                if inp.name not in data:
                    data[inp.name] = inp.value or ''

            response = self._make_request('POST', target_url, data=data)
            if response and (response.status_code == 429 or response.status_code == 403):
                blocked = True
                break

        if not blocked:
            return self._build_vuln(
                name='No Brute Force Protection',
                severity='medium',
                category='Authentication',
                description='The login form does not implement rate limiting or account lockout '
                           'after multiple failed attempts.',
                impact='Attackers can perform brute force attacks to guess user credentials.',
                remediation='Implement account lockout after 5-10 failed attempts. '
                           'Add rate limiting. Use CAPTCHA after failed attempts. '
                           'Consider progressive delays.',
                cwe='CWE-307',
                cvss=5.3,
                affected_url=target_url,
                evidence='6 rapid failed login attempts were accepted without rate limiting or lockout.',
            )
        return None

    def _test_account_enumeration(self, form, page_url):
        """Test if the application reveals whether a username exists."""
        username_field = None
        password_field = None

        for inp in form.inputs:
            if inp.input_type == 'password':
                password_field = inp.name
            elif inp.input_type in ('text', 'email') or (
                inp.name and any(k in inp.name.lower() for k in ('user', 'email', 'login'))
            ):
                username_field = inp.name

        if not username_field or not password_field:
            return None

        target_url = form.action or page_url

        # Try a valid-looking username
        data1 = {username_field: 'admin', password_field: 'wrongpassword123!'}
        for inp in form.inputs:
            if inp.name not in data1:
                data1[inp.name] = inp.value or ''

        # Try a random non-existent username
        data2 = {username_field: 'nonexistentuser9827364', password_field: 'wrongpassword123!'}
        for inp in form.inputs:
            if inp.name not in data2:
                data2[inp.name] = inp.value or ''

        resp1 = self._make_request('POST', target_url, data=data1)
        resp2 = self._make_request('POST', target_url, data=data2)

        if resp1 and resp2:
            # Compare responses — different error messages indicate enumeration
            body1 = resp1.text.lower()
            body2 = resp2.text.lower()

            enum_hints = [
                'user not found', 'invalid username', 'no account',
                'username does not exist', 'account not found',
                'incorrect password', 'wrong password',
            ]

            for hint in enum_hints:
                in1 = hint in body1
                in2 = hint in body2
                if in1 != in2:
                    return self._build_vuln(
                        name='Account Enumeration via Login',
                        severity='low',
                        category='Authentication',
                        description='The login form reveals whether a username/email exists through different error messages.',
                        impact='Attackers can determine valid usernames for use in targeted attacks.',
                        remediation='Use generic error messages like "Invalid credentials" for all failed login attempts.',
                        cwe='CWE-204',
                        cvss=3.7,
                        affected_url=target_url,
                        evidence=f'Different error responses for existing vs non-existing usernames.',
                    )
        return None

    def _check_http_login(self, page):
        """Check if login credentials are sent over HTTP."""
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type == 'password':
                    return self._build_vuln(
                        name='Login Form Over Unencrypted HTTP',
                        severity='high',
                        category='Authentication',
                        description='Login credentials are transmitted over unencrypted HTTP.',
                        impact='Credentials can be intercepted by network attackers (man-in-the-middle).',
                        remediation='Serve all login pages and form submissions over HTTPS.',
                        cwe='CWE-319',
                        cvss=7.5,
                        affected_url=page.url,
                        evidence=f'Login form found on HTTP page: {page.url}',
                    )
        return None

    def _check_password_autocomplete(self, page):
        """Check if password fields allow autocomplete."""
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type == 'password':
                    # In a real check we'd inspect the autocomplete attribute
                    # This is informational only
                    pass
        return None

    def _is_login_success(self, response):
        """Heuristic to determine if login was successful."""
        if response.status_code in (301, 302, 303):
            location = response.headers.get('Location', '')
            if any(k in location.lower() for k in ('dashboard', 'home', 'welcome', 'profile', 'account')):
                return True
        if response.status_code == 200:
            body = response.text.lower()
            if any(k in body for k in ('welcome', 'dashboard', 'logout', 'sign out')):
                if 'invalid' not in body and 'error' not in body and 'failed' not in body:
                    return True
        return False
