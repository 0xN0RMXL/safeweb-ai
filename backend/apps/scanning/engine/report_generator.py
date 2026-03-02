"""
PDF and report generation for scan results.
"""
import io
import csv
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def generate_json_report(scan) -> str:
    """Generate JSON export of scan results."""
    from apps.scanning.serializers import ScanDetailSerializer
    serializer = ScanDetailSerializer(scan)
    return json.dumps(serializer.data, indent=2, default=str)


def generate_csv_report(scan) -> str:
    """Generate CSV export of vulnerability data."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        'Name', 'Severity', 'Category', 'CWE', 'CVSS',
        'Affected URL', 'Description', 'Impact', 'Remediation',
    ])

    for vuln in scan.vulnerabilities.all():
        writer.writerow([
            vuln.name,
            vuln.severity,
            vuln.category,
            vuln.cwe or '',
            vuln.cvss or '',
            vuln.affected_url or '',
            vuln.description,
            vuln.impact,
            vuln.remediation,
        ])

    return output.getvalue()


def generate_pdf_report(scan) -> bytes:
    """Generate PDF report of scan results."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, mm
        from reportlab.lib.colors import HexColor
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )
        from reportlab.lib import colors
    except ImportError:
        logger.error('reportlab not installed — PDF generation unavailable')
        raise ImportError('reportlab is required for PDF export')

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=25 * mm,
        leftMargin=25 * mm,
        topMargin=30 * mm,
        bottomMargin=25 * mm,
    )

    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=HexColor('#1a1a2e'),
        spaceAfter=6,
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=HexColor('#16213e'),
        spaceAfter=12,
        spaceBefore=20,
    )
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=HexColor('#0f3460'),
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        spaceAfter=8,
    )

    severity_colors = {
        'critical': HexColor('#dc2626'),
        'high': HexColor('#ea580c'),
        'medium': HexColor('#d97706'),
        'low': HexColor('#2563eb'),
        'info': HexColor('#6b7280'),
    }

    # ---- Title Page ----
    elements.append(Spacer(1, 60))
    elements.append(Paragraph('SafeWeb AI', title_style))
    elements.append(Paragraph('Security Scan Report', heading_style))
    elements.append(HRFlowable(width='100%', thickness=2, color=HexColor('#6366f1')))
    elements.append(Spacer(1, 20))

    # Scan info table
    scan_info = [
        ['Target', scan.target],
        ['Scan Type', scan.get_scan_type_display()],
        ['Status', scan.get_status_display()],
        ['Score', f'{scan.score}/100' if scan.score is not None else 'N/A'],
        ['Started', scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'],
        ['Completed', scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A'],
        ['Scan ID', str(scan.id)],
    ]
    info_table = Table(scan_info, colWidths=[100, 350])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#374151')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, HexColor('#e5e7eb')),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 30))

    # ---- Vulnerability Summary ----
    vulnerabilities = scan.vulnerabilities.all()
    summary = scan.vulnerability_summary

    elements.append(Paragraph('Vulnerability Summary', heading_style))

    summary_data = [
        ['Severity', 'Count'],
        ['Critical', str(summary.get('critical', 0))],
        ['High', str(summary.get('high', 0))],
        ['Medium', str(summary.get('medium', 0))],
        ['Low', str(summary.get('low', 0))],
        ['Info', str(summary.get('info', 0))],
        ['Total', str(summary.get('total', 0))],
    ]

    summary_table = Table(summary_data, colWidths=[120, 80])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f3f4f6')),
        ('TEXTCOLOR', (0, 1), (0, 1), severity_colors['critical']),
        ('TEXTCOLOR', (0, 2), (0, 2), severity_colors['high']),
        ('TEXTCOLOR', (0, 3), (0, 3), severity_colors['medium']),
        ('TEXTCOLOR', (0, 4), (0, 4), severity_colors['low']),
        ('TEXTCOLOR', (0, 5), (0, 5), severity_colors['info']),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#d1d5db')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    elements.append(summary_table)
    elements.append(PageBreak())

    # ---- Detailed Findings ----
    elements.append(Paragraph('Detailed Findings', heading_style))
    elements.append(Spacer(1, 10))

    for i, vuln in enumerate(vulnerabilities, 1):
        sev_color = severity_colors.get(vuln.severity, HexColor('#6b7280'))

        elements.append(Paragraph(
            f'{i}. {vuln.name}',
            subheading_style,
        ))

        # Severity badge
        sev_style = ParagraphStyle(
            'SevBadge', parent=body_style,
            textColor=sev_color, fontName='Helvetica-Bold',
        )
        elements.append(Paragraph(
            f'Severity: {vuln.severity.upper()}'
            f' | CVSS: {vuln.cvss or "N/A"}'
            f' | CWE: {vuln.cwe or "N/A"}'
            f' | Category: {vuln.category}',
            sev_style,
        ))

        if vuln.affected_url:
            elements.append(Paragraph(
                f'<b>Affected URL:</b> {vuln.affected_url}', body_style
            ))

        elements.append(Paragraph(f'<b>Description:</b> {vuln.description}', body_style))
        elements.append(Paragraph(f'<b>Impact:</b> {vuln.impact}', body_style))
        elements.append(Paragraph(f'<b>Remediation:</b> {vuln.remediation}', body_style))

        if vuln.evidence:
            evidence_text = str(vuln.evidence).replace('\n', '<br/>').replace('<', '&lt;').replace('>', '&gt;').replace('&lt;br/&gt;', '<br/>')
            elements.append(Paragraph(f'<b>Evidence:</b><br/>{evidence_text}', body_style))

        elements.append(HRFlowable(width='100%', thickness=0.5, color=HexColor('#e5e7eb')))
        elements.append(Spacer(1, 10))

    # ---- Footer ----
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width='100%', thickness=1, color=HexColor('#6366f1')))
    footer_style = ParagraphStyle(
        'Footer', parent=body_style,
        fontSize=8, textColor=HexColor('#9ca3af'), alignment=TA_CENTER,
    )
    elements.append(Paragraph(
        f'Generated by SafeWeb AI on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        footer_style,
    ))
    elements.append(Paragraph(
        'This report is for authorized use only. Findings should be verified manually.',
        footer_style,
    ))

    doc.build(elements)
    return buffer.getvalue()
