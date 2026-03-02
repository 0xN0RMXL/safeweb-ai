import logging
from django.utils import timezone
from django.db.models import Count, Avg, Q
from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser

from .models import Scan, Vulnerability
from .serializers import (
    ScanCreateSerializer, ScanURLCreateSerializer,
    ScanDetailSerializer, ScanListSerializer,
)
from .tasks import execute_scan_task
from apps.accounts.utils import time_ago

logger = logging.getLogger(__name__)


class WebsiteScanCreateView(views.APIView):
    """POST /api/scan/website — Create a new website scan."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        assert serializer.validated_data is not None
        data = serializer.validated_data

        scan = Scan.objects.create(
            user=request.user,
            scan_type='website',
            target=data['url'],
            depth=data['scan_depth'],
            include_subdomains=data['include_subdomains'],
            check_ssl=data['check_ssl'],
            follow_redirects=data['follow_redirects'],
            status='pending',
        )

        # Dispatch async scan task
        execute_scan_task.delay(str(scan.id))

        logger.info(f'Website scan created: {scan.id} for {scan.target} by {request.user.email}')

        return Response({
            'id': str(scan.id),
            'target': scan.target,
            'type': 'website',
            'status': 'pending',
            'startTime': timezone.now().isoformat(),
            'message': 'Scan initiated. Use GET /api/scan/{id} to check progress.',
        }, status=status.HTTP_201_CREATED)


class FileScanCreateView(views.APIView):
    """POST /api/scan/file — Upload and scan a file for malware."""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return Response(
                {'detail': 'No file provided.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate file size (50MB)
        if uploaded_file.size > 50 * 1024 * 1024:
            return Response(
                {'detail': 'File size exceeds 50MB limit.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scan = Scan.objects.create(
            user=request.user,
            scan_type='file',
            target=uploaded_file.name,
            uploaded_file=uploaded_file,
            status='pending',
        )

        execute_scan_task.delay(str(scan.id))
        logger.info(f'File scan created: {scan.id} for {uploaded_file.name}')

        return Response({
            'id': str(scan.id),
            'target': uploaded_file.name,
            'type': 'file',
            'status': 'pending',
            'startTime': timezone.now().isoformat(),
        }, status=status.HTTP_201_CREATED)


class URLScanCreateView(views.APIView):
    """POST /api/scan/url — Scan a URL for phishing."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ScanURLCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan = Scan.objects.create(
            user=request.user,
            scan_type='url',
            target=serializer.validated_data['url'],  # type: ignore[index]
            status='pending',
        )

        execute_scan_task.delay(str(scan.id))
        logger.info(f'URL scan created: {scan.id} for {scan.target}')

        return Response({
            'id': str(scan.id),
            'target': scan.target,
            'type': 'url',
            'status': 'pending',
            'startTime': timezone.now().isoformat(),
        }, status=status.HTTP_201_CREATED)


class ScanDetailView(generics.RetrieveAPIView):
    """GET /api/scan/{id} — Get scan results."""
    serializer_class = ScanDetailSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):  # type: ignore[override]
        return Scan.objects.filter(user=self.request.user).prefetch_related('vulnerabilities')


class ScanDeleteView(views.APIView):
    """DELETE /api/scan/{id} — Delete a scan."""
    permission_classes = [IsAuthenticated]

    def delete(self, request, id):
        try:
            scan = Scan.objects.get(id=id, user=request.user)
            scan.delete()
            return Response({'detail': 'Scan deleted successfully.'})
        except Scan.DoesNotExist:
            return Response(
                {'detail': 'Scan not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )


class RescanView(views.APIView):
    """POST /api/scan/{id}/rescan — Re-run a scan with same config."""
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            original = Scan.objects.get(id=id, user=request.user)
        except Scan.DoesNotExist:
            return Response(
                {'detail': 'Scan not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        new_scan = Scan.objects.create(
            user=request.user,
            scan_type=original.scan_type,
            target=original.target,
            depth=original.depth,
            include_subdomains=original.include_subdomains,
            check_ssl=original.check_ssl,
            follow_redirects=original.follow_redirects,
            status='pending',
        )

        try:
            execute_scan_task.delay(str(new_scan.id))
        except Exception as e:
            logger.error(f'Rescan task failed for {new_scan.id}: {e}')
            # The task/orchestrator already sets status to 'failed' on error,
            # but refresh from DB just in case
            new_scan.refresh_from_db()
            if new_scan.status != 'failed':
                new_scan.status = 'failed'
                new_scan.error_message = str(e)
                new_scan.save(update_fields=['status', 'error_message'])

        # Always return the new scan — frontend will poll for status
        new_scan.refresh_from_db()
        return Response({
            'id': str(new_scan.id),
            'status': new_scan.status,
            'target': new_scan.target,
            'type': new_scan.scan_type,
            'message': 'Re-scan initiated.' if new_scan.status != 'failed' else 'Re-scan completed with errors.',
        }, status=status.HTTP_201_CREATED)


class ScanExportView(views.APIView):
    """GET /api/scan/{id}/export?format=pdf|json|csv"""
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        try:
            scan = Scan.objects.get(id=id, user=request.user)
        except Scan.DoesNotExist:
            return Response(
                {'detail': 'Scan not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        export_format = request.query_params.get('export_format', 'json')

        if export_format == 'json':
            return self._export_json(scan)
        elif export_format == 'csv':
            return self._export_csv(scan)
        elif export_format == 'pdf':
            return self._export_pdf(scan)
        else:
            return Response(
                {'detail': f'Unsupported format: {export_format}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _export_json(self, scan):
        from django.http import JsonResponse
        serializer = ScanDetailSerializer(scan)
        response = JsonResponse(serializer.data, json_dumps_params={'indent': 2})
        response['Content-Disposition'] = f'attachment; filename="safeweb-scan-{scan.id}.json"'
        return response

    def _export_csv(self, scan):
        import csv
        from django.http import HttpResponse
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="safeweb-scan-{scan.id}.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Name', 'Severity', 'Category', 'CWE', 'CVSS',
            'Affected URL', 'Description', 'Impact', 'Remediation',
        ])

        for vuln in scan.vulnerabilities.all():
            writer.writerow([
                vuln.name, vuln.severity, vuln.category, vuln.cwe, vuln.cvss,
                vuln.affected_url, vuln.description, vuln.impact, vuln.remediation,
            ])

        return response

    def _export_pdf(self, scan):
        from django.http import HttpResponse
        try:
            from apps.scanning.engine.report_generator import generate_pdf_report
            pdf_buffer = generate_pdf_report(scan)
        except ImportError:
            logger.error('reportlab is not installed — cannot generate PDF')
            return Response(
                {'detail': 'PDF export is not available. The reportlab package is not installed.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f'PDF generation failed for scan {scan.id}: {e}')
            return Response(
                {'detail': f'Failed to generate PDF report: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        response = HttpResponse(pdf_buffer, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="safeweb-scan-report-{scan.id}.pdf"'
        return response


# ── Scan List / History ──────────────────────────────

class ScanListView(generics.ListAPIView):
    """GET /api/scans — List user's scan history."""
    serializer_class = ScanListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):  # type: ignore[override]
        queryset = Scan.objects.filter(user=self.request.user)

        # Search filter
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(target__icontains=search)

        # Status filter
        scan_status = self.request.query_params.get('status')
        if scan_status and scan_status != 'all':
            queryset = queryset.filter(status=scan_status)

        # Type filter
        scan_type = self.request.query_params.get('type')
        if scan_type and scan_type != 'all':
            queryset = queryset.filter(scan_type=scan_type.lower())

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            paginated = self.get_paginated_response(serializer.data)
            # Add stats
            all_scans = Scan.objects.filter(user=request.user)
            paginated.data['stats'] = {
                'total': all_scans.count(),
                'completed': all_scans.filter(status='completed').count(),
                'failed': all_scans.filter(status='failed').count(),
                'avgScore': all_scans.filter(status='completed').aggregate(
                    avg=Avg('score')
                )['avg'] or 0,
            }
            return paginated

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# ── Dashboard ──────────────────────────────

class DashboardView(views.APIView):
    """GET /api/dashboard — Dashboard stats for current user."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        scans = Scan.objects.filter(user=user)
        total_scans = scans.count()
        completed_scans = scans.filter(status='completed')

        # Critical issues count
        critical_count = Vulnerability.objects.filter(
            scan__user=user, severity='critical'
        ).count()

        # Average security score
        avg_score = completed_scans.aggregate(avg=Avg('score'))['avg'] or 0

        # Last scan time
        last_scan = scans.order_by('-created_at').first()
        last_scan_time = time_ago(last_scan.created_at) if last_scan else 'Never'

        # Compute 7-day change percentages
        from django.utils import timezone as tz
        from datetime import timedelta
        week_ago = tz.now() - timedelta(days=7)
        two_weeks_ago = tz.now() - timedelta(days=14)
        scans_this_week = scans.filter(created_at__gte=week_ago).count()
        scans_last_week = scans.filter(created_at__gte=two_weeks_ago, created_at__lt=week_ago).count()
        scans_change = ''
        if scans_last_week > 0:
            pct = ((scans_this_week - scans_last_week) / scans_last_week) * 100
            scans_change = f'+{pct:.1f}%' if pct >= 0 else f'{pct:.1f}%'
        elif scans_this_week > 0:
            scans_change = '+100%'

        critical_this_week = Vulnerability.objects.filter(
            scan__user=user, severity='critical', scan__created_at__gte=week_ago
        ).count()
        critical_last_week = Vulnerability.objects.filter(
            scan__user=user, severity='critical',
            scan__created_at__gte=two_weeks_ago, scan__created_at__lt=week_ago
        ).count()
        critical_change = ''
        if critical_last_week > 0:
            pct = ((critical_this_week - critical_last_week) / critical_last_week) * 100
            critical_change = f'+{pct:.1f}%' if pct >= 0 else f'{pct:.1f}%'
        elif critical_this_week > 0:
            critical_change = '+100%'

        completed_this_week = completed_scans.filter(created_at__gte=week_ago)
        completed_last_week = completed_scans.filter(
            created_at__gte=two_weeks_ago, created_at__lt=week_ago
        )
        score_this = completed_this_week.aggregate(avg=Avg('score'))['avg'] or 0
        score_last = completed_last_week.aggregate(avg=Avg('score'))['avg'] or 0
        score_change = ''
        if score_last > 0:
            pct = ((score_this - score_last) / score_last) * 100
            score_change = f'+{pct:.1f}%' if pct >= 0 else f'{pct:.1f}%'
        elif score_this > 0:
            score_change = 'New'

        # Recent scans (top 5)
        recent = ScanListSerializer(
            scans.order_by('-created_at')[:5], many=True
        ).data

        # Vulnerability overview
        vuln_counts = Vulnerability.objects.filter(scan__user=user).values(
            'severity'
        ).annotate(count=Count('id'))
        vuln_overview = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for item in vuln_counts:
            vuln_overview[item['severity']] = item['count']

        return Response({
            'stats': {
                'totalScans': total_scans,
                'criticalIssues': critical_count,
                'securityScore': round(avg_score),
                'lastScan': last_scan_time,
                'scansChange': scans_change,
                'criticalChange': critical_change,
                'scoreChange': score_change,
            },
            'recentScans': recent,
            'vulnerabilityOverview': vuln_overview,
        })
