"""
ScanOrchestrator — Main scan coordinator.
Manages the entire scan lifecycle: crawl → analyze → test → score → report.
"""
import logging
from django.utils import timezone

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Coordinates all scanning phases for a given scan job."""

    def execute_scan(self, scan_id: str):
        """Main entry point — executes the complete scan workflow."""
        from apps.scanning.models import Scan
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'scanning'
        scan.started_at = timezone.now()
        scan.save(update_fields=['status', 'started_at'])

        logger.info(f'Scan orchestrator started: {scan.id} ({scan.scan_type}) → {scan.target}')

        try:
            if scan.scan_type == 'website':
                self._scan_website(scan)
            elif scan.scan_type == 'file':
                self._scan_file(scan)
            elif scan.scan_type == 'url':
                self._scan_url(scan)

            scan.status = 'completed'
            scan.score = self._calculate_security_score(scan)
            logger.info(f'Scan completed: {scan.id} — score {scan.score}')

        except Exception as e:
            scan.status = 'failed'
            scan.error_message = str(e)
            logger.error(f'Scan failed: {scan.id} — {e}', exc_info=True)

        finally:
            scan.completed_at = timezone.now()
            if scan.started_at:
                scan.duration = int((scan.completed_at - scan.started_at).total_seconds())
            scan.save()

    def _scan_website(self, scan):
        """Execute a full website vulnerability scan."""
        from apps.scanning.models import Vulnerability
        from apps.scanning.engine.crawler import WebCrawler
        from apps.scanning.engine.analyzers.header_analyzer import HeaderAnalyzer
        from apps.scanning.engine.analyzers.ssl_analyzer import SSLAnalyzer
        from apps.scanning.engine.analyzers.cookie_analyzer import CookieAnalyzer
        from apps.scanning.engine.testers import get_all_testers

        # Phase 1: Crawl the target website
        logger.info(f'Phase 1: Crawling {scan.target}')
        crawler = WebCrawler(
            base_url=scan.target,
            depth=scan.depth,
            follow_redirects=scan.follow_redirects,
            include_subdomains=scan.include_subdomains,
        )
        pages = crawler.crawl()
        logger.info(f'Crawled {len(pages)} pages')

        # Phase 2: Analyze headers
        logger.info(f'Phase 2: Analyzing headers')
        header_analyzer = HeaderAnalyzer()
        header_vulns = header_analyzer.analyze(scan.target)
        for vuln_data in header_vulns:
            Vulnerability.objects.create(scan=scan, **vuln_data)

        # Phase 3: SSL analysis
        if scan.check_ssl:
            logger.info(f'Phase 3: SSL analysis')
            ssl_analyzer = SSLAnalyzer()
            ssl_vulns = ssl_analyzer.analyze(scan.target)
            for vuln_data in ssl_vulns:
                Vulnerability.objects.create(scan=scan, **vuln_data)

        # Phase 4: Cookie analysis
        logger.info(f'Phase 4: Cookie analysis')
        cookie_analyzer = CookieAnalyzer()
        cookie_vulns = cookie_analyzer.analyze(scan.target)
        for vuln_data in cookie_vulns:
            Vulnerability.objects.create(scan=scan, **vuln_data)

        # Phase 5: Test each page for vulnerabilities
        logger.info(f'Phase 5: Running vulnerability testers on {len(pages)} pages')
        testers = get_all_testers()
        for page in pages:
            for tester in testers:
                try:
                    vulns = tester.test(page, scan.depth)
                    for vuln_data in vulns:
                        Vulnerability.objects.create(scan=scan, **vuln_data)
                except Exception as e:
                    logger.warning(f'Tester {tester.__class__.__name__} failed on {page.url}: {e}')

    def _scan_file(self, scan):
        """Execute file malware detection using ML."""
        from apps.ml.malware_detector import MalwareDetector

        logger.info(f'File scan: {scan.target}')
        detector = MalwareDetector()

        with open(scan.uploaded_file.path, 'rb') as f:
            file_content = f.read()
        result = detector.predict(file_content, filename=scan.target, scan=scan)

    def _scan_url(self, scan):
        """Execute URL phishing detection using ML."""
        from apps.ml.phishing_detector import PhishingDetector

        logger.info(f'URL scan: {scan.target}')
        detector = PhishingDetector()
        result = detector.predict(scan.target, scan=scan)

    def _calculate_security_score(self, scan):
        """Calculate 0-100 security score based on vulnerability severity."""
        vulns = scan.vulnerabilities.all()
        if not vulns.exists():
            return 100

        penalty = 0
        for vuln in vulns:
            if vuln.severity == 'critical':
                penalty += 25
            elif vuln.severity == 'high':
                penalty += 15
            elif vuln.severity == 'medium':
                penalty += 8
            elif vuln.severity == 'low':
                penalty += 3

        return max(0, 100 - penalty)
