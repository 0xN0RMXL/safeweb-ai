"""
Vulnerability Testers Package.
Each tester implements the BaseTester interface and tests for specific OWASP vulnerabilities.
"""
from .sqli_tester import SQLInjectionTester
from .xss_tester import XSSTester
from .csrf_tester import CSRFTester
from .auth_tester import AuthTester
from .misconfig_tester import MisconfigTester
from .data_exposure_tester import DataExposureTester
from .access_control_tester import AccessControlTester
from .ssrf_tester import SSRFTester
from .component_tester import ComponentTester
from .logging_tester import LoggingTester


def get_all_testers():
    """Return instances of all vulnerability testers."""
    return [
        SQLInjectionTester(),
        XSSTester(),
        CSRFTester(),
        AuthTester(),
        MisconfigTester(),
        DataExposureTester(),
        AccessControlTester(),
        SSRFTester(),
        ComponentTester(),
        LoggingTester(),
    ]
