"""Live scan test — validates the full scanner pipeline end-to-end."""
import os, sys, json, django, time

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
os.environ['DJANGO_ALLOW_ASYNC_UNSAFE'] = 'true'
django.setup()

from apps.scanning.models import Scan, Vulnerability
from apps.accounts.models import User

# ── 1. Setup ──────────────────────────────────────────────────────────
user, _ = User.objects.get_or_create(
    email='test@safeweb.ai',
    defaults={'username': 'test_scanner', 'is_active': True},
)
if not user.has_usable_password():
    user.set_password('testpass123')
    user.save()

scan = Scan.objects.create(
    user=user,
    scan_type='website',
    target='http://testphp.vulnweb.com/',
    depth='medium',
    include_subdomains=False,
    check_ssl=False,
    follow_redirects=True,
    status='pending',
)
print(f'\n{"="*70}')
print(f'  SafeWeb AI — Live Scan Test')
print(f'  Scan ID : {scan.id}')
print(f'  Target  : {scan.target}')
print(f'  Depth   : {scan.depth}')
print(f'{"="*70}\n')

# ── 2. Execute (synchronous — no Celery needed) ──────────────────────
from apps.scanning.engine.orchestrator import ScanOrchestrator

start = time.time()
try:
    orchestrator = ScanOrchestrator()
    orchestrator.execute_scan(str(scan.id))
except Exception as exc:
    print(f'\n[ERROR] Scan failed: {exc}')
    import traceback; traceback.print_exc()

elapsed = time.time() - start

# ── 3. Report ─────────────────────────────────────────────────────────
scan.refresh_from_db()
vulns = Vulnerability.objects.filter(scan=scan).order_by('-cvss', '-severity')

print(f'\n{"="*70}')
print(f'  SCAN RESULTS')
print(f'{"="*70}')
print(f'  Status   : {scan.status}')
print(f'  Score    : {scan.score}/100')
print(f'  Duration : {elapsed:.1f}s')
print(f'  Pages    : {scan.pages_crawled}')
print(f'  Requests : {scan.total_requests}')
print(f'  Findings : {vulns.count()}')
if scan.error_message:
    print(f'  Error    : {scan.error_message}')
print()

# Severity breakdown
sev_counts = {}
for v in vulns:
    sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1
for sev in ['critical', 'high', 'medium', 'low', 'info']:
    cnt = sev_counts.get(sev, 0)
    if cnt:
        print(f'  {sev.upper():10s}: {cnt}')

print(f'\n{"-"*70}')
print(f'  VULNERABILITY DETAILS')
print(f'{"-"*70}')

for i, v in enumerate(vulns[:30], 1):
    has_exploit = bool(v.exploit_data)
    exploit_tag = ' [EXPLOITED]' if has_exploit else ''
    print(f'\n  {i}. [{v.severity.upper()}] {v.name}{exploit_tag}')
    print(f'     Category : {v.category}')
    print(f'     CVSS     : {v.cvss}')
    print(f'     CWE      : {v.cwe}')
    print(f'     URL      : {v.affected_url}')
    print(f'     Verified : {v.verified}')
    if has_exploit:
        ed = v.exploit_data
        expl = ed.get('exploit', {})
        rpt = ed.get('report', {})
        print(f'     Exploit Success : {expl.get("success")}')
        print(f'     Exploit Type    : {expl.get("exploit_type")}')
        print(f'     Impact Proof    : {(expl.get("impact_proof") or "")[:120]}')
        print(f'     BB Report       : {"LLM-enhanced" if rpt.get("llm_enhanced") else "Template-based"}')
        if expl.get('extracted_data'):
            print(f'     Extracted Data  : {json.dumps(expl["extracted_data"], default=str)[:200]}')

# ── 4. Phase stats ───────────────────────────────────────────────────
if scan.recon_data and '_stats' in scan.recon_data:
    print(f'\n{"-"*70}')
    print(f'  PHASE TIMING')
    print(f'{"-"*70}')
    for phase, secs in scan.recon_data['_stats'].items():
        print(f'  {phase:20s}: {secs:.1f}s')

# ── 5. Exploit report samples ────────────────────────────────────────
exploited = [v for v in vulns if v.exploit_data]
if exploited:
    print(f'\n{"="*70}')
    print(f'  BUG BOUNTY REPORT SAMPLES ({len(exploited)} exploited findings)')
    print(f'{"="*70}')
    for v in exploited[:3]:
        rpt = v.exploit_data.get('report', {})
        md = rpt.get('markdown', '')
        if md:
            print(f'\n--- {v.name} ---')
            print(md[:800])
            if len(md) > 800:
                print(f'  ... [truncated, {len(md)} chars total]')

print(f'\n{"="*70}')
print(f'  DONE — Scan {scan.id}')
print(f'{"="*70}\n')
