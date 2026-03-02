import uuid
from django.db import models
from django.conf import settings


class Scan(models.Model):
    """Scan job model — tracks a security scan request and its results."""
    SCAN_TYPES = [('website', 'Website'), ('file', 'File'), ('url', 'URL')]
    SCAN_STATUSES = [
        ('pending', 'Pending'),
        ('scanning', 'Scanning'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    SCAN_DEPTHS = [('shallow', 'Shallow'), ('medium', 'Medium'), ('deep', 'Deep')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='scans',
    )
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    target = models.TextField()  # URL or filename
    status = models.CharField(max_length=20, choices=SCAN_STATUSES, default='pending')
    depth = models.CharField(max_length=20, choices=SCAN_DEPTHS, default='medium')
    include_subdomains = models.BooleanField(default=False)
    check_ssl = models.BooleanField(default=True)
    follow_redirects = models.BooleanField(default=True)
    score = models.IntegerField(default=0)  # 0-100 security score
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.IntegerField(default=0)  # seconds
    error_message = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    # File upload (for file scans)
    uploaded_file = models.FileField(upload_to='scan_files/', null=True, blank=True)

    class Meta:
        db_table = 'scans'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.scan_type} scan: {self.target} ({self.status})'

    @property
    def vulnerability_summary(self):
        """Return vulnerability count by severity."""
        from django.db.models import Count
        counts = self.vulnerabilities.values('severity').annotate(count=Count('id'))
        summary = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for item in counts:
            summary[item['severity']] = item['count']
            summary['total'] += item['count']
        return summary


class Vulnerability(models.Model):
    """Individual vulnerability finding from a scan."""
    SEVERITIES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITIES)
    category = models.CharField(max_length=100)
    description = models.TextField()
    impact = models.TextField()
    remediation = models.TextField()
    cwe = models.CharField(max_length=20, blank=True, default='')
    cvss = models.FloatField(default=0.0)
    affected_url = models.URLField(max_length=2048, blank=True, default='')
    evidence = models.TextField(blank=True, default='')
    is_false_positive = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vulnerabilities'
        ordering = ['-cvss', 'severity']
        verbose_name_plural = 'vulnerabilities'

    def __str__(self):
        return f'{self.severity.upper()}: {self.name}'


class ScanReport(models.Model):
    """Generated reports for scans."""
    FORMATS = [
        ('pdf', 'PDF'),
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('xml', 'XML'),
        ('html', 'HTML'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='reports')
    format = models.CharField(max_length=10, choices=FORMATS)
    file = models.FileField(upload_to='reports/')
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'scan_reports'
        ordering = ['-generated_at']

    def __str__(self):
        return f'{self.format.upper()} report for {self.scan.target}'
