import logging
from celery import shared_task

logger = logging.getLogger(__name__)


# ── Phase 43: Scheduled & Continuous Scanning ─────────────────────────────────

@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def execute_scheduled_scan_task(self, scheduled_scan_id: str):
    """
    Execute a single ScheduledScan entry and update its last_run / next_run
    fields (Phase 43).
    """
    from django.utils import timezone as dj_tz
    from apps.scanning.models import ScheduledScan, Scan
    from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine

    logger.info(f'Starting scheduled scan task: {scheduled_scan_id}')
    try:
        scheduled = ScheduledScan.objects.get(id=scheduled_scan_id)
    except ScheduledScan.DoesNotExist:
        logger.error(f'ScheduledScan not found: {scheduled_scan_id}')
        return

    if not scheduled.is_active:
        logger.info(f'Scheduled scan {scheduled_scan_id} is inactive — skipping.')
        return

    now = dj_tz.now()
    config = scheduled.scan_config or {}

    try:
        # Build the child Scan record from the schedule config
        scan = Scan.objects.create(
            user=scheduled.user,
            scan_type=config.get('scan_type', 'website'),
            target=config.get('target', ''),
            depth=config.get('depth', 'medium'),
            include_subdomains=config.get('include_subdomains', False),
            status='pending',
        )

        # Kick off the actual scan
        execute_scan_task.delay(str(scan.id))

        # Update scheduling timestamps
        engine = ScheduledScanEngine()
        next_run = engine.compute_next_run(
            scheduled.cron_expr or scheduled.schedule_preset, from_dt=now,
        )
        scheduled.last_run = now
        scheduled.next_run = next_run
        scheduled.save(update_fields=['last_run', 'next_run'])

        logger.info(
            f'Scheduled scan {scheduled_scan_id} dispatched scan {scan.id}. '
            f'Next run: {next_run.isoformat()}'
        )
    except Exception as exc:
        logger.error(f'Scheduled scan {scheduled_scan_id} failed: {exc}')
        if self.request.retries >= self.max_retries:
            return
        raise self.retry(exc=exc)


@shared_task
def run_scheduled_scans():
    """
    Periodic (Celery Beat) task that finds all due ScheduledScan entries and
    dispatches each as an ``execute_scheduled_scan_task`` (Phase 43).
    """
    from django.utils import timezone as dj_tz
    from apps.scanning.models import ScheduledScan

    now = dj_tz.now()
    due = ScheduledScan.objects.filter(is_active=True, next_run__lte=now)
    count = 0
    for scheduled in due:
        execute_scheduled_scan_task.delay(str(scheduled.id))
        count += 1
    logger.info(f'run_scheduled_scans dispatched {count} scheduled scan(s).')
    return {'dispatched': count}


@shared_task
def compute_scan_diff_task(scan_id: str, baseline_scan_id: str) -> dict:
    """
    Compute a differential analysis between two scans and return a summary
    dict (Phase 43).
    """
    from apps.scanning.models import Vulnerability
    from apps.scanning.engine.scan_comparison import ScanComparison, compute_security_posture

    def _findings(sid):
        return list(
            Vulnerability.objects.filter(scan_id=sid).values(
                'name', 'severity', 'category', 'affected_url', 'cvss', 'cwe',
            )
        )

    baseline_findings = _findings(baseline_scan_id)
    current_findings = _findings(scan_id)

    comparison = ScanComparison(baseline_findings, current_findings).compare()
    posture = compute_security_posture(current_findings)

    result = comparison.to_dict()
    result['security_posture'] = posture
    result['scan_id'] = scan_id
    result['baseline_scan_id'] = baseline_scan_id

    logger.info(
        f'Scan diff computed: scan={scan_id} vs baseline={baseline_scan_id} — '
        f'new={result["new"]}, fixed={result["fixed"]}'
    )
    return result


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def execute_scan_task(self, scan_id):
    """Execute a scan asynchronously via Celery.

    The orchestrator internally uses asyncio.run() for async phases,
    so Celery workers don't need any async configuration.
    """
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


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def execute_scan_chunk_task(self, chunk_data: dict) -> dict:
    """
    Phase 15: Execute a single ScanChunk on a Celery worker.

    chunk_data keys: chunk_id, scan_id, chunk_type, payload
    Returns the result dict from ScanWorker.execute_chunk().
    """
    from apps.scanning.engine.distributed.scan_controller import ScanChunk
    from apps.scanning.engine.distributed.worker import ScanWorker

    chunk_id = chunk_data.get('chunk_id', 'unknown')
    logger.info(f'Starting chunk task: {chunk_id}')

    chunk = ScanChunk(
        chunk_id=chunk_data['chunk_id'],
        scan_id=chunk_data['scan_id'],
        chunk_type=chunk_data['chunk_type'],
        payload=chunk_data.get('payload', {}),
    )

    def progress_cb(state, meta):
        self.update_state(state=state, meta=meta)

    worker = ScanWorker(chunk, progress_cb=progress_cb)
    try:
        result = worker.execute_chunk()
        logger.info(f'Chunk task completed: {chunk_id}')
        return result
    except Exception as exc:
        logger.error(f'Chunk task failed: {chunk_id} — {exc}')
        if self.request.retries >= self.max_retries:
            return {'error': str(exc), 'chunk_id': chunk_id}
        raise self.retry(exc=exc)

