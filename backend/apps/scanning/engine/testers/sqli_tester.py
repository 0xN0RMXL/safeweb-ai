"""
SQLInjectionTester — Tests for SQL Injection vulnerabilities.
OWASP A03:2021 — Injection.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Detection-only payloads — NO destructive operations
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 OR 1=1",
    "' OR ''='",
    "admin'--",
    "1' AND SLEEP(3) --",
    "1; WAITFOR DELAY '0:0:3' --",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "' UNION SELECT NULL,NULL,NULL --",
]

SQLI_ERROR_PATTERNS = [
    re.compile(r'SQL syntax.*MySQL', re.IGNORECASE),
    re.compile(r'Warning.*mysql_', re.IGNORECASE),
    re.compile(r'PostgreSQL.*ERROR', re.IGNORECASE),
    re.compile(r'ORA-\d{5}', re.IGNORECASE),
    re.compile(r'Microsoft.*ODBC.*SQL Server', re.IGNORECASE),
    re.compile(r'Unclosed quotation mark', re.IGNORECASE),
    re.compile(r'quoted string not properly terminated', re.IGNORECASE),
    re.compile(r'SQLite.*error', re.IGNORECASE),
    re.compile(r'SQLSTATE\[', re.IGNORECASE),
    re.compile(r'pg_query.*ERROR', re.IGNORECASE),
    re.compile(r'System\.Data\.SqlClient', re.IGNORECASE),
    re.compile(r'Syntax error.*in query', re.IGNORECASE),
    re.compile(r'mysql_fetch', re.IGNORECASE),
    re.compile(r'num_rows', re.IGNORECASE),
]


class SQLInjectionTester(BaseTester):
    """Test for SQL injection vulnerabilities in forms and URL parameters."""

    TESTER_NAME = 'SQL Injection'

    def test(self, page, depth: str = 'medium') -> list:
        vulnerabilities = []
        payloads = SQLI_PAYLOADS[:5] if depth == 'shallow' else SQLI_PAYLOADS

        # Test URL parameters
        for param_name, param_values in page.parameters.items():
            for payload in payloads:
                vuln = self._test_parameter(page.url, param_name, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # One finding per parameter

        # Test form inputs
        for form in page.forms:
            for inp in form.inputs:
                if inp.input_type in ('hidden', 'submit', 'button', 'image', 'file'):
                    continue
                for payload in payloads:
                    vuln = self._test_form_input(form, inp, payload, page.url)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # One finding per input

        return vulnerabilities

    def _test_parameter(self, url, param_name, payload):
        """Test a URL parameter for SQL injection."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = payload

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params, doseq=True), ''
        ))

        response = self._make_request('GET', test_url)
        if response and self._check_sqli_indicators(response):
            return self._build_vuln(
                name=f'SQL Injection in URL Parameter: {param_name}',
                severity='critical',
                category='Injection',
                description=f'The URL parameter "{param_name}" is vulnerable to SQL injection. '
                           f'The application includes user input in SQL queries without proper sanitization.',
                impact='An attacker could read, modify, or delete database contents, bypass authentication, '
                      'or execute administrative operations on the database.',
                remediation='Use parameterized queries (prepared statements) instead of string concatenation. '
                           'In Python: cursor.execute("SELECT * FROM users WHERE id = %s", [user_id]). '
                           'Use an ORM like Django ORM or SQLAlchemy that handles parameterization automatically.',
                cwe='CWE-89',
                cvss=9.8,
                affected_url=url,
                evidence=f'Payload: {param_name}={payload}\nResponse contained SQL error indicators.',
            )
        return None

    def _test_form_input(self, form, inp, payload, page_url):
        """Test a form input for SQL injection."""
        data = {}
        for form_inp in form.inputs:
            if form_inp.name == inp.name:
                data[form_inp.name] = payload
            else:
                data[form_inp.name] = form_inp.value or 'test'

        method = form.method.upper()
        target_url = form.action or page_url

        if method == 'POST':
            response = self._make_request('POST', target_url, data=data)
        else:
            response = self._make_request('GET', target_url, params=data)

        if response and self._check_sqli_indicators(response):
            return self._build_vuln(
                name=f'SQL Injection in Form Field: {inp.name}',
                severity='critical',
                category='Injection',
                description=f'The form field "{inp.name}" at {target_url} is vulnerable to SQL injection.',
                impact='An attacker could bypass authentication, extract sensitive data from the database, '
                      'modify or delete records, or execute system commands.',
                remediation='Use parameterized queries or an ORM. Never concatenate user input into SQL strings. '
                           'Apply input validation and use stored procedures where appropriate.',
                cwe='CWE-89',
                cvss=9.8,
                affected_url=target_url,
                evidence=f'Form: {form.method} {target_url}\nField: {inp.name}\nPayload: {payload}',
            )
        return None

    def _check_sqli_indicators(self, response):
        """Check if response indicates SQL injection vulnerability."""
        if not response or not response.text:
            return False

        body = response.text

        # Check for SQL error messages
        for pattern in SQLI_ERROR_PATTERNS:
            if pattern.search(body):
                return True

        # Check for time-based blind injection (response took > 2.5s)
        if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > 2.5:
            return True

        return False
