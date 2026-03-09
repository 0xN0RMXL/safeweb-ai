"""Test the full API pipeline: auth → scan detail → verify exploit_data in response."""
import os, sys, json, requests, time

BASE_URL = 'http://localhost:8000'

print("=" * 60)
print("  SafeWeb AI — API Pipeline Test")
print("=" * 60)

# 1. Get JWT token
print("\n[1] Getting JWT token...")
resp = requests.post(
    f'{BASE_URL}/api/auth/login/',
    json={'email': 'test@safeweb.ai', 'password': 'testpass123'},
    timeout=10,
)
if resp.status_code != 200:
    print(f"  ERROR: Login failed ({resp.status_code}): {resp.text[:200]}")
    sys.exit(1)

data_login = resp.json()
# Response is {'user': {...}, 'tokens': {'access': ..., 'refresh': ...}}
token = (data_login.get('tokens') or data_login).get('access', '')
print(f"  OK — Token: {token[:40]}...")
headers = {'Authorization': f'Bearer {token}'}

# 2. List scans
print("\n[2] Listing scans...")
resp = requests.get(f'{BASE_URL}/api/scans/', headers=headers, timeout=10)
print(f"  Status: {resp.status_code}")
if resp.status_code == 200:
    scans = resp.json()
    items = scans.get('results', scans) if isinstance(scans, dict) else scans
    print(f"  Scans in list: {len(items)}")
    for sc in items[:3]:
        print(f"    [{sc.get('status','?')}] {sc.get('id','')} — {sc.get('target','')} ({sc.get('score',0)} pts, {sc.get('duration',0)}s)")
else:
    print(f"  ERROR: {resp.text[:300]}")
    sys.exit(1)

# 3. Get the most recent scan detail
if not items:
    print("\n  No scans found — scan may still be running")
    sys.exit(0)

scan_id = items[0]['id']
print(f"\n[3] Getting scan detail for {scan_id}...")
resp = requests.get(f'{BASE_URL}/api/scan/{scan_id}/', headers=headers, timeout=15)
print(f"  Status: {resp.status_code}")
if resp.status_code != 200:
    print(f"  ERROR: {resp.text[:300]}")
    sys.exit(1)

data = resp.json()
print(f"  Scan status: {data.get('status')}")
print(f"  Score: {data.get('score')}/100")
print(f"  Duration: {data.get('duration')}s")
print(f"  Pages crawled: {data.get('pages_crawled')}")
print(f"  Total requests: {data.get('total_requests')}")
vulns = data.get('vulnerabilities', [])
print(f"  Vulnerabilities in API: {len(vulns)}")

# 4. Check vulnerability structure
print("\n[4] Checking vulnerability structure...")
has_exploit_data_key = all('exploit_data' in v for v in vulns[:3]) if vulns else None
print(f"  exploit_data key present in all vulns: {has_exploit_data_key}")

exploited = [v for v in vulns if v.get('exploit_data')]
verified = [v for v in vulns if v.get('verified')]
print(f"  Verified vulns: {len(verified)}")
print(f"  Vulns with exploit_data: {len(exploited)}")

# Severity breakdown
sev = {}
for v in vulns:
    sev[v.get('severity','?')] = sev.get(v.get('severity','?'), 0) + 1
print(f"  Severity breakdown: {json.dumps(sev)}")

print("\n[5] Top vulns:")
for v in sorted(vulns, key=lambda x: (x.get('cvss',0) or 0), reverse=True)[:10]:
    tag = '[E]' if v.get('exploit_data') else '[ ]'
    vtag = '[V]' if v.get('verified') else '[ ]'
    url = (v.get('affected_url') or '-')[:45]
    print(f"  {tag}{vtag} [{v.get('severity','?').upper():8s}] {v.get('name','')[:50]:50s} | {url}")

if exploited:
    print("\n[6] Exploit data sample:")
    v = exploited[0]
    ed = v['exploit_data']
    expl = ed.get('exploit', {}) if ed else {}
    rpt = ed.get('report', {}) if ed else {}
    print(f"  Vuln: {v['name']}")
    print(f"  exploit.success: {expl.get('success')}")
    print(f"  exploit.type: {expl.get('exploit_type')}")
    print(f"  exploit.poc (truncated): {str(expl.get('poc',''))[:100]}")
    print(f"  exploit.steps count: {len(expl.get('steps', []))}")
    print(f"  report.markdown (chars): {len(rpt.get('markdown',''))}")
    print(f"  report.llm_enhanced: {rpt.get('llm_enhanced')}")
    print()
    print("  ✅ Full pipeline verified: scan → DB → API → exploit_data present in response")
else:
    print("\n[6] No exploit data yet")
    print("  (Scan may still be running or no verified high/critical vulns found)")
    # Check tester results
    trs = data.get('tester_results') or []
    passed = [t for t in trs if t.get('status') == 'passed' and t.get('findingsCount', 0) > 0]
    print(f"  Testers with findings: {[t['testerName'] for t in passed[:5]]}")

# 7. Check API response structure matches frontend expectations
print("\n[7] Frontend compatibility check:")
if vulns:
    first = vulns[0]
    REQUIRED_FRONTEND_KEYS = ['id', 'name', 'severity', 'category', 'description',
                               'impact', 'remediation', 'cwe', 'cvss', 'affected_url',
                               'evidence', 'is_false_positive', 'verified', 
                               'false_positive_score', 'attack_chain', 'exploit_data']
    missing = [k for k in REQUIRED_FRONTEND_KEYS if k not in first]
    if missing:
        print(f"  MISSING KEYS: {missing}")
    else:
        print(f"  ✅ All {len(REQUIRED_FRONTEND_KEYS)} required frontend keys present")
    
    # Check exploit_data structure matches TypeScript interface
    if exploited:
        ed = exploited[0]['exploit_data']
        expl = ed.get('exploit', {})
        rpt = ed.get('report', {})
        ts_exploit_keys = ['success', 'exploit_type', 'extracted_data', 'poc', 'steps', 'impact_proof']
        ts_report_keys = ['markdown', 'structured', 'llm_enhanced']
        missing_e = [k for k in ts_exploit_keys if k not in expl]
        missing_r = [k for k in ts_report_keys if k not in rpt]
        print(f"  exploit TS interface keys missing: {missing_e or 'none'}")
        print(f"  report TS interface keys missing: {missing_r or 'none'}")

print("\n" + "=" * 60)
print("  API TEST COMPLETE")
print("=" * 60)
