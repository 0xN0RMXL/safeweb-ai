from rest_framework import serializers
from .models import Scan, Vulnerability, ScanReport


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Serializer for vulnerability details."""
    affected_url = serializers.URLField(required=False, allow_blank=True)

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'name', 'severity', 'category', 'description',
            'impact', 'remediation', 'cwe', 'cvss', 'affected_url',
            'evidence',
        ]


class ScanCreateSerializer(serializers.Serializer):
    """Serializer for creating a new website scan."""
    url = serializers.URLField()
    scan_depth = serializers.ChoiceField(
        choices=['shallow', 'medium', 'deep'],
        default='medium',
    )
    include_subdomains = serializers.BooleanField(default=False)
    check_ssl = serializers.BooleanField(default=True)
    follow_redirects = serializers.BooleanField(default=True)


class ScanURLCreateSerializer(serializers.Serializer):
    """Serializer for URL phishing scan."""
    url = serializers.URLField()


class ScanDetailSerializer(serializers.ModelSerializer):
    """Detailed scan result — matches ScanResults.tsx structure."""
    type = serializers.CharField(source='scan_type')
    start_time = serializers.DateTimeField(source='started_at')
    end_time = serializers.DateTimeField(source='completed_at')
    summary = serializers.SerializerMethodField()
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    scan_options = serializers.SerializerMethodField()
    ml_result = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'target', 'type', 'status', 'start_time', 'end_time',
            'duration', 'score', 'summary', 'vulnerabilities', 'scan_options',
            'ml_result',
        ]

    def get_summary(self, obj):
        return obj.vulnerability_summary

    def get_scan_options(self, obj):
        return {
            'depth': obj.depth,
            'includeSubdomains': obj.include_subdomains,
            'checkSsl': obj.check_ssl,
        }

    def get_ml_result(self, obj):
        try:
            result = obj.ml_predictions.order_by('-created_at').first()
            if result:
                return {
                    'prediction': result.prediction,
                    'confidence': result.confidence,
                    'modelUsed': result.model.name if result.model else 'rule-based',
                }
        except Exception:
            pass
        return None


class ScanListSerializer(serializers.ModelSerializer):
    """Scan list item — matches ScanHistory.tsx structure."""
    type = serializers.CharField(source='get_scan_type_display')
    date = serializers.DateTimeField(source='created_at')
    vulnerabilities = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'target', 'type', 'status', 'date',
            'duration', 'score', 'vulnerabilities',
        ]

    def get_vulnerabilities(self, obj):
        return obj.vulnerability_summary
