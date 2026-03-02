from django.contrib import admin
from .models import Scan, Vulnerability, ScanReport


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'scan_type', 'target', 'status', 'score', 'created_at']
    list_filter = ['scan_type', 'status', 'depth']
    search_fields = ['target', 'user__email']
    readonly_fields = ['id', 'created_at']


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['name', 'severity', 'category', 'cvss', 'scan', 'created_at']
    list_filter = ['severity', 'category']
    search_fields = ['name', 'cwe']


@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = ['scan', 'format', 'generated_at']
    list_filter = ['format']
