"""
BaseTester — Abstract base class for all vulnerability testers.
"""
import logging
import time
import requests

logger = logging.getLogger(__name__)


class BaseTester:
    """Abstract base class that all vulnerability testers inherit from."""

    # Override in subclasses
    TESTER_NAME = 'Base'
    REQUEST_TIMEOUT = 10
    MAX_TESTS_PER_PAGE = 50

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SafeWeb AI Scanner/1.0 (Security Assessment)',
        })
        self.session.verify = False

    def test(self, page, depth: str = 'medium') -> list:
        """
        Test a single page for vulnerabilities.
        Returns a list of vulnerability dicts ready for Vulnerability.objects.create().
        """
        raise NotImplementedError('Subclasses must implement test()')

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request with timeout and error handling."""
        kwargs.setdefault('timeout', self.REQUEST_TIMEOUT)
        kwargs.setdefault('allow_redirects', False)

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            response = self.session.request(method, url, **kwargs)
            time.sleep(0.3)  # Rate limiting
            return response
        except requests.exceptions.Timeout:
            logger.debug(f'Request timeout: {method} {url}')
            return None
        except Exception as e:
            logger.debug(f'Request error: {method} {url}: {e}')
            return None

    def _build_vuln(self, name, severity, category, description, impact,
                    remediation, cwe, cvss, affected_url, evidence):
        """Build a vulnerability dict."""
        return {
            'name': name,
            'severity': severity,
            'category': category,
            'description': description,
            'impact': impact,
            'remediation': remediation,
            'cwe': cwe,
            'cvss': cvss,
            'affected_url': affected_url,
            'evidence': evidence[:2000],  # Truncate evidence
        }
