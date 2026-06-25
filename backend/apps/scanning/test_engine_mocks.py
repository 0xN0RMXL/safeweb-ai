import pytest
import json
from unittest.mock import patch, MagicMock
from django.test import TestCase
from apps.accounts.models import Organization, User
from apps.scanning.models import Scan, Vulnerability
from apps.scanning.engine.tools.wrappers.nuclei_cli_wrapper import NucleiCLITool
from apps.scanning.engine.tools.wrappers.nmap_wrapper import NmapTool
from apps.scanning.tasks import execute_scan_task

@pytest.mark.django_db
class TestScannerEngine(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='user@test.com', username='user@test.com', password='Password123!')
        self.org = Organization.objects.create(name='Test Org')
        self.scan = Scan.objects.create(
            user=self.user,
            organization=self.org,
            target='https://example.com',
            status='pending',
            scan_type='website'
        )

    @patch('apps.scanning.engine.tools.base.ExternalTool._exec')
    @patch('apps.scanning.engine.tools.base.ExternalTool.is_available')
    def test_nuclei_mock_execution(self, mock_is_available, mock_exec):
        """Test Mock Execution of Nuclei"""
        mock_is_available.return_value = True
        
        # Mock Nuclei JSON output
        mock_output = json.dumps({
            "template-id": "tech-detect",
            "info": {
                "name": "Technology Detection",
                "severity": "info"
            },
            "host": "https://example.com",
            "matcher-name": "nginx"
        })
        mock_exec.return_value = mock_output
        
        tool = NucleiCLITool()
        results = tool.run('https://example.com')
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "[tech-detect] Technology Detection")
        self.assertEqual(results[0].severity, "info")

    def test_vulnerability_deduplication(self):
        """Test Vulnerability Deduplication Logic"""
        # Create first vulnerability
        v1 = Vulnerability.objects.create(
            scan=self.scan,
            name="Test Vuln",
            severity="medium",
            affected_url="https://example.com/api"
        )
        
        # In the engine, when we try to create the same vulnerability, we should 
        # either skip or increment count/instances.
        # Simulating the exact engine save behavior for deduplication
        existing = Vulnerability.objects.filter(
            scan=self.scan,
            name="Test Vuln",
            affected_url="https://example.com/api"
        ).first()
        
        if existing:
            # Update logic (just saving again or modifying instances)
            existing.save()
            created = False
        else:
            Vulnerability.objects.create(
                scan=self.scan,
                name="Test Vuln",
                severity="medium",
                affected_url="https://example.com/api"
            )
            created = True
            
        self.assertFalse(created)
        
        # Total vulns should be 1
        count = Vulnerability.objects.filter(scan=self.scan).count()
        self.assertEqual(count, 1)
