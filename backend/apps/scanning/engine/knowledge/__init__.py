"""
Knowledge Base Package — Phase 41.

Exposes:
  VulnKB            — vulnerability information database
  RemediationKB     — remediation and compliance mapping database
  VULNERABILITY_DB  — raw vulnerability dict (CWE → record)
  REMEDIATION_DB    — raw remediation dict (CWE → record)
  COMPLIANCE_MAP    — raw compliance dict (CWE → framework controls)
"""
from .vuln_kb import VulnKB, VULNERABILITY_DB
from .remediation_kb import RemediationKB, REMEDIATION_DB, COMPLIANCE_MAP

__all__ = [
    'VulnKB',
    'RemediationKB',
    'VULNERABILITY_DB',
    'REMEDIATION_DB',
    'COMPLIANCE_MAP',
]
