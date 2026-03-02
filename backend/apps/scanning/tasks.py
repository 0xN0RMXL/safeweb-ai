import logging
from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def execute_scan_task(self, scan_id):
    """Execute a scan asynchronously via Celery."""
    from apps.scanning.engine.orchestrator import ScanOrchestrator
    from apps.scanning.models import Scan

    logger.info(f'Starting scan task: {scan_id}')
    try:
        orchestrator = ScanOrchestrator()
        orchestrator.execute_scan(scan_id)
        logger.info(f'Scan completed: {scan_id}')
    except Scan.DoesNotExist:
        logger.error(f'Scan not found: {scan_id}')
        return  # Don't retry — permanent failure
    except Exception as exc:
        logger.error(f'Scan failed: {scan_id} — {exc}')
        try:
            scan = Scan.objects.get(id=scan_id)
            if self.request.retries >= self.max_retries:
                scan.status = 'failed'
                scan.error_message = str(exc)
                scan.save(update_fields=['status', 'error_message'])
                return  # Final failure — don't retry
            else:
                scan.error_message = f'Retry {self.request.retries + 1}: {exc}'
                scan.save(update_fields=['error_message'])
        except Scan.DoesNotExist:
            return
        raise self.retry(exc=exc)
