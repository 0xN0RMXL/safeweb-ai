"""
ComponentTester — Tests for vulnerable and outdated components.
OWASP A06:2021 — Vulnerable and Outdated Components.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# Known vulnerable version patterns (simplified)
KNOWN_VULNERABLE = {
    'Apache': {
        'pattern': r'Apache/(\d+\.\d+\.\d+)',
        'vulnerable_below': '2.4.54',
        'cve': 'CVE-2022-31813',
    },
    'nginx': {
        'pattern': r'nginx/(\d+\.\d+\.\d+)',
        'vulnerable_below': '1.23.0',
        'cve': 'CVE-2022-41741',
    },
    'PHP': {
        'pattern': r'PHP/(\d+\.\d+\.\d+)',
        'vulnerable_below': '8.1.0',
        'cve': 'Multiple CVEs',
    },
    'jQuery': {
        'pattern': r'jquery[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '3.5.0',
        'cve': 'CVE-2020-11023',
    },
    'Bootstrap': {
        'pattern': r'bootstrap[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '4.3.1',
        'cve': 'CVE-2019-8331',
    },
    'WordPress': {
        'pattern': r'WordPress\s+(\d+\.\d+)',
        'vulnerable_below': '6.0',
        'cve': 'Multiple CVEs',
    },
}

FRAMEWORK_HEADERS = {
    'X-Powered-By': 'Technology stack disclosure',
    'Server': 'Web server disclosure',
    'X-AspNet-Version': 'ASP.NET version disclosure',
    'X-AspNetMvc-Version': 'ASP.NET MVC version disclosure',
    'X-Drupal-Cache': 'Drupal CMS detected',
    'X-Generator': 'CMS/framework disclosure',
}


class ComponentTester(BaseTester):
    """Test for vulnerable and outdated components."""

    TESTER_NAME = 'Components'

    def test(self, page, depth: str = 'medium') -> list:
        vulnerabilities = []

        # Check response headers for server/framework versions
        response = self._make_request('GET', page.url)
        if response:
            vulns = self._check_server_headers(response, page.url)
            vulnerabilities.extend(vulns)

        # Check page source for library versions
        if depth in ('medium', 'deep'):
            vulns = self._check_client_libraries(page)
            vulnerabilities.extend(vulns)

        # Check for common CMS fingerprints
        vulns = self._check_cms_fingerprints(page)
        vulnerabilities.extend(vulns)

        # Check for outdated TLS
        vuln = self._check_deprecated_features(page)
        if vuln:
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_server_headers(self, response, url):
        """Check for version information in response headers."""
        vulnerabilities = []

        for header, description in FRAMEWORK_HEADERS.items():
            value = response.headers.get(header, '')
            if not value:
                continue

            # Check if it reveals a version number
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', value)

            # Check against known vulnerable versions
            for component, info in KNOWN_VULNERABLE.items():
                match = re.search(info['pattern'], value, re.IGNORECASE)
                if match:
                    detected_version = match.group(1)
                    if self._is_version_below(detected_version, info['vulnerable_below']):
                        vulnerabilities.append(self._build_vuln(
                            name=f'Vulnerable {component} Version: {detected_version}',
                            severity='high',
                            category='Vulnerable Components',
                            description=f'{component} version {detected_version} is outdated and has known vulnerabilities.',
                            impact=f'Known vulnerabilities ({info["cve"]}) may allow remote code execution, '
                                  f'denial of service, or data disclosure.',
                            remediation=f'Update {component} to the latest stable version.',
                            cwe='CWE-1104',
                            cvss=7.5,
                            affected_url=url,
                            evidence=f'{header}: {value}',
                        ))
                        break

            # General version disclosure
            if version_match and not any(v['name'] == f'Vulnerable {c} Version' for c in KNOWN_VULNERABLE for v in vulnerabilities if 'name' in v):
                vulnerabilities.append(self._build_vuln(
                    name=f'Technology Version Disclosed: {header}',
                    severity='low',
                    category='Vulnerable Components',
                    description=f'{description}. Value: {value}',
                    impact='Version information helps attackers find known vulnerabilities '
                          'specific to the detected version.',
                    remediation=f'Remove or suppress the {header} header in production. '
                               'Configure the web server to not reveal version information.',
                    cwe='CWE-200',
                    cvss=3.7,
                    affected_url=url,
                    evidence=f'{header}: {value}',
                ))

        return vulnerabilities

    def _check_client_libraries(self, page):
        """Check for vulnerable client-side libraries in page source."""
        vulnerabilities = []
        body = page.body

        for component, info in KNOWN_VULNERABLE.items():
            match = re.search(info['pattern'], body, re.IGNORECASE)
            if match:
                detected_version = match.group(1)
                if self._is_version_below(detected_version, info['vulnerable_below']):
                    vulnerabilities.append(self._build_vuln(
                        name=f'Vulnerable Client Library: {component} {detected_version}',
                        severity='medium',
                        category='Vulnerable Components',
                        description=f'{component} version {detected_version} is outdated and vulnerable.',
                        impact=f'Known vulnerabilities ({info["cve"]}) in this library may be exploited.',
                        remediation=f'Update {component} to the latest version. '
                                   'Use a dependency management tool to track updates.',
                        cwe='CWE-1104',
                        cvss=6.1,
                        affected_url=page.url,
                        evidence=f'Detected {component} version {detected_version} in page source.',
                    ))

        return vulnerabilities

    def _check_cms_fingerprints(self, page):
        """Check for CMS fingerprints that reveal technology."""
        vulnerabilities = []
        body = page.body

        cms_patterns = {
            'WordPress': [
                r'wp-content/', r'wp-includes/', r'wp-json/',
                r'<meta name="generator" content="WordPress\s+([\d.]+)"',
            ],
            'Drupal': [
                r'sites/default/files/', r'Drupal\.settings',
                r'<meta name="generator" content="Drupal\s+([\d.]+)"',
            ],
            'Joomla': [
                r'/media/jui/', r'/components/com_',
                r'<meta name="generator" content="Joomla',
            ],
        }

        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else 'unknown'
                    vulnerabilities.append(self._build_vuln(
                        name=f'CMS Detected: {cms}',
                        severity='info',
                        category='Vulnerable Components',
                        description=f'{cms} CMS detected (version: {version}). '
                                   f'This information helps attackers target known CMS vulnerabilities.',
                        impact='Knowing the CMS and version allows attackers to use specific exploits.',
                        remediation=f'Keep {cms} updated to the latest version. '
                                   'Remove version information from meta tags.',
                        cwe='CWE-200',
                        cvss=3.1,
                        affected_url=page.url,
                        evidence=f'{cms} fingerprint detected via pattern: {pattern}',
                    ))
                    break  # One finding per CMS

        return vulnerabilities

    def _check_deprecated_features(self, page):
        """Check for deprecated/insecure features in page source."""
        body = page.body

        deprecated_patterns = {
            'document.domain': 'Deprecated DOM property that weakens same-origin policy',
            'X-UA-Compatible': 'Targets old IE versions, indicating legacy support',
        }

        for pattern, description in deprecated_patterns.items():
            if pattern in body:
                return self._build_vuln(
                    name=f'Deprecated Feature: {pattern}',
                    severity='info',
                    category='Vulnerable Components',
                    description=f'{description}.',
                    impact='Use of deprecated features may introduce security weaknesses.',
                    remediation='Remove deprecated features and update to modern alternatives.',
                    cwe='CWE-477',
                    cvss=2.0,
                    affected_url=page.url,
                    evidence=f'Deprecated feature "{pattern}" found in page source.',
                )
        return None

    def _is_version_below(self, version, threshold):
        """Compare version strings (semver-like)."""
        try:
            v_parts = [int(x) for x in version.split('.')]
            t_parts = [int(x) for x in threshold.split('.')]
            # Pad shorter list
            while len(v_parts) < len(t_parts):
                v_parts.append(0)
            while len(t_parts) < len(v_parts):
                t_parts.append(0)
            return v_parts < t_parts
        except (ValueError, AttributeError):
            return False
