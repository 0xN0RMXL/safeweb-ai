import { useState, useEffect, useRef } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import { formatDateTime } from '@utils/date';
import { scanAPI } from '@/services/api';

export default function ScanResults() {
    const { id } = useParams();
    const navigate = useNavigate();
    const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
    const [isLoading, setIsLoading] = useState(true);
    const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
    const statusRef = useRef('scanning');

    const [scanData, setScanData] = useState({
        id: id || '',
        target: '',
        type: 'Website',
        status: 'scanning',
        startTime: new Date(),
        endTime: new Date(),
        duration: 0,
        score: 0,
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
    });

    const [vulnerabilities, setVulnerabilities] = useState<{
        id: string; name: string; severity: 'critical' | 'high' | 'medium' | 'low';
        category: string; cwe: string; cvss: number; url: string;
        description: string; impact: string; remediation: string; evidence: string;
    }[]>([]);

    useEffect(() => {
        if (!id) return;

        const fetchResults = () => {
            scanAPI.getResults(id).then(({ data }) => {
                setScanData({
                    id: data.id,
                    target: data.target,
                    type: data.scanType || data.type || 'Website',
                    status: data.status,
                    startTime: new Date(data.startedAt || data.createdAt),
                    endTime: data.completedAt ? new Date(data.completedAt) : new Date(),
                    duration: data.duration || 0,
                    score: data.score || 0,
                    summary: data.vulnerabilitySummary || data.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
                });

                if (data.vulnerabilities) {
                    setVulnerabilities(data.vulnerabilities.map((v: Record<string, unknown>) => ({
                        id: v.id,
                        name: v.name || v.title,
                        severity: v.severity,
                        category: v.category,
                        cwe: v.cweId || v.cwe || '',
                        cvss: v.cvssScore || v.cvss || 0,
                        url: v.url || v.affectedUrl || '',
                        description: v.description || '',
                        impact: v.impact || '',
                        remediation: v.remediation || '',
                        evidence: v.evidence || '',
                    })));
                }

                // Stop polling when scan completes
                if (data.status === 'completed' || data.status === 'failed') {
                    setIsLoading(false);
                    statusRef.current = data.status;
                }
            }).catch(() => setIsLoading(false));
        };

        fetchResults();

        // Poll for updates while scan is in progress
        const interval = setInterval(() => {
            if (statusRef.current === 'completed' || statusRef.current === 'failed') {
                clearInterval(interval);
                return;
            }
            fetchResults();
        }, 5000);
        pollRef.current = interval;

        return () => clearInterval(interval);
    }, [id]);

    // Clean up polling when status changes to completed
    useEffect(() => {
        if ((scanData.status === 'completed' || scanData.status === 'failed') && pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
        }
    }, [scanData.status]);

    const handleExport = async (format: string) => {
        if (!id) return;
        try {
            const { data } = await scanAPI.exportScan(id, format);

            // For blob responses (PDF, CSV), check if it's actually an error
            if (data instanceof Blob) {
                // If the blob is JSON (error response), read it
                if (data.type === 'application/json') {
                    const text = await data.text();
                    const err = JSON.parse(text);
                    alert(err.detail || 'Export failed.');
                    return;
                }
                const mimeTypes: Record<string, string> = {
                    pdf: 'application/pdf',
                    csv: 'text/csv',
                };
                const blob = new Blob([data], { type: mimeTypes[format] || data.type });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `scan-report-${id}.${format}`;
                a.click();
                URL.revokeObjectURL(url);
            } else {
                // JSON format
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `scan-report-${id}.json`;
                a.click();
                URL.revokeObjectURL(url);
            }
        } catch (err: unknown) {
            console.error('Export failed:', err);
            let message = 'Failed to export report. Please try again.';
            if (err && typeof err === 'object' && 'response' in err) {
                const resp = (err as { response?: { data?: { detail?: string } } }).response;
                if (resp?.data?.detail) message = resp.data.detail;
            }
            alert(message);
        }
    };

    const handleRescan = async () => {
        if (!id) return;
        try {
            const { data } = await scanAPI.rescan(id);
            if (data.id) {
                // Navigate to the new scan results and let polling handle status updates
                navigate(`/scan/results/${data.id}`);
                // Force a page reload so polling restarts for the new scan
                window.location.href = `/scan/results/${data.id}`;
            } else {
                alert('Re-scan failed. Please try again.');
            }
        } catch (err: unknown) {
            console.error('Rescan failed:', err);
            let message = 'Failed to start rescan. Please try again.';
            if (err && typeof err === 'object' && 'response' in err) {
                const resp = (err as { response?: { data?: { detail?: string } } }).response;
                if (resp?.data?.detail) message = resp.data.detail;
            }
            alert(message);
        }
    };

    const filteredVulnerabilities = selectedSeverity === 'all'
        ? vulnerabilities
        : vulnerabilities.filter((v) => v.severity === selectedSeverity);

    const getSeverityColor = (severity: string) => {
        const colors = {
            critical: 'text-status-critical',
            high: 'text-status-high',
            medium: 'text-status-medium',
            low: 'text-status-low',
        };
        return colors[severity as keyof typeof colors] || 'text-text-tertiary';
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {isLoading && scanData.target === '' ? (
                        <div className="flex items-center justify-center py-20">
                            <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                            <span className="ml-3 text-text-secondary">Loading scan results...</span>
                        </div>
                    ) : (
                    <>
                    {/* Header */}
                    <div className="flex flex-col md:flex-row md:items-start md:justify-between mb-8">
                        <div>
                            <Link to="/history" className="text-sm text-accent-green hover:text-accent-green-hover mb-2 inline-flex items-center gap-1">
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                                </svg>
                                Back to History
                            </Link>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                Scan Results
                            </h1>
                            <p className="text-text-secondary font-mono text-sm">
                                {scanData.target}
                            </p>
                        </div>
                        <div className="flex items-center gap-3 mt-4 md:mt-0">
                            <Button variant="outline" size="sm" onClick={() => handleExport('pdf')}>
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                </svg>
                                Export PDF
                            </Button>
                            <Button variant="primary" size="sm" onClick={handleRescan}>
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                </svg>
                                Re-scan
                            </Button>
                        </div>
                    </div>

                    {/* Summary Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
                        <Card className="p-6 text-center">
                            <div className="text-4xl font-bold text-accent-green mb-2">{scanData.score}</div>
                            <div className="text-sm text-text-tertiary">Security Score</div>
                        </Card>
                        <Card className="p-6 text-center">
                            <div className={`text-4xl font-bold mb-2 ${getSeverityColor('critical')}`}>
                                {scanData.summary.critical}
                            </div>
                            <div className="text-sm text-text-tertiary">Critical</div>
                        </Card>
                        <Card className="p-6 text-center">
                            <div className={`text-4xl font-bold mb-2 ${getSeverityColor('high')}`}>
                                {scanData.summary.high}
                            </div>
                            <div className="text-sm text-text-tertiary">High</div>
                        </Card>
                        <Card className="p-6 text-center">
                            <div className={`text-4xl font-bold mb-2 ${getSeverityColor('medium')}`}>
                                {scanData.summary.medium}
                            </div>
                            <div className="text-sm text-text-tertiary">Medium</div>
                        </Card>
                        <Card className="p-6 text-center">
                            <div className={`text-4xl font-bold mb-2 ${getSeverityColor('low')}`}>
                                {scanData.summary.low}
                            </div>
                            <div className="text-sm text-text-tertiary">Low</div>
                        </Card>
                    </div>

                    {/* Scan Info */}
                    <Card className="p-6 mb-8">
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                            <div>
                                <div className="text-sm text-text-tertiary mb-1">Start Time</div>
                                <div className="text-sm text-text-primary font-mono">
                                    {formatDateTime(scanData.startTime)}
                                </div>
                            </div>
                            <div>
                                <div className="text-sm text-text-tertiary mb-1">End Time</div>
                                <div className="text-sm text-text-primary font-mono">
                                    {formatDateTime(scanData.endTime)}
                                </div>
                            </div>
                            <div>
                                <div className="text-sm text-text-tertiary mb-1">Duration</div>
                                <div className="text-sm text-text-primary font-mono">{scanData.duration} minutes</div>
                            </div>
                            <div>
                                <div className="text-sm text-text-tertiary mb-1">Status</div>
                                <Badge
                                    variant={scanData.status === 'completed' ? 'low' : scanData.status === 'failed' ? 'critical' : 'info'}
                                    size="sm"
                                >
                                    {scanData.status === 'completed' ? 'Completed' : scanData.status === 'failed' ? 'Failed' : 'Scanning...'}
                                </Badge>
                            </div>
                        </div>
                    </Card>

                    {/* Filter */}
                    <div className="flex items-center gap-3 mb-6">
                        <span className="text-sm text-text-tertiary">Filter by severity:</span>
                        <div className="flex items-center gap-2">
                            {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
                                <button
                                    key={severity}
                                    onClick={() => setSelectedSeverity(severity)}
                                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${selectedSeverity === severity
                                            ? 'bg-accent-green text-bg-primary'
                                            : 'bg-bg-secondary text-text-secondary hover:bg-bg-hover'
                                        }`}
                                >
                                    {severity.charAt(0).toUpperCase() + severity.slice(1)}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Failed Scan Error */}
                    {scanData.status === 'failed' && (
                        <Card className="p-6 mb-6 border-status-critical/30 bg-status-critical/5">
                            <div className="flex items-start gap-3">
                                <svg className="w-6 h-6 text-status-critical flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                                <div>
                                    <h3 className="text-lg font-semibold text-status-critical mb-1">Scan Failed</h3>
                                    <p className="text-sm text-text-secondary">This scan encountered an error and could not complete. Please try running the scan again.</p>
                                </div>
                            </div>
                        </Card>
                    )}

                    {/* Vulnerabilities List */}
                    <div className="space-y-4">
                        {filteredVulnerabilities.length === 0 && scanData.status === 'completed' && (
                            <Card className="p-12 text-center">
                                <svg className="w-16 h-16 mx-auto text-status-low mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <h3 className="text-xl font-heading font-semibold text-text-primary mb-2">No Vulnerabilities Found</h3>
                                <p className="text-text-secondary">Great news! No security vulnerabilities were detected in this scan.</p>
                            </Card>
                        )}
                        {filteredVulnerabilities.map((vuln) => (
                            <Card key={vuln.id} className="p-6 hover:shadow-card-hover transition-all duration-300">
                                <div className="flex items-start justify-between mb-4">
                                    <div className="flex-1">
                                        <div className="flex items-center gap-3 mb-2">
                                            <h3 className="text-lg font-heading font-semibold text-text-primary">
                                                {vuln.name}
                                            </h3>
                                            <Badge variant={vuln.severity}>{vuln.severity.toUpperCase()}</Badge>
                                        </div>
                                        <div className="flex items-center gap-4 text-sm text-text-tertiary">
                                            <span className="font-mono">{vuln.cwe}</span>
                                            <span>•</span>
                                            <span>CVSS Score: {vuln.cvss}</span>
                                            <span>•</span>
                                            <span>{vuln.category}</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-4">
                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Description</h4>
                                        <p className="text-sm text-text-secondary leading-relaxed">{vuln.description}</p>
                                    </div>

                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Affected URL</h4>
                                        <code className="text-sm text-accent-green font-mono bg-bg-secondary px-3 py-1 rounded">
                                            {vuln.url}
                                        </code>
                                    </div>

                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Impact</h4>
                                        <p className="text-sm text-text-secondary leading-relaxed">{vuln.impact}</p>
                                    </div>

                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Remediation</h4>
                                        <p className="text-sm text-text-secondary leading-relaxed">{vuln.remediation}</p>
                                    </div>

                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Evidence</h4>
                                        <pre className="text-xs text-text-secondary bg-bg-secondary p-4 rounded-lg overflow-x-auto font-mono border border-border-primary">
                                            {vuln.evidence}
                                        </pre>
                                    </div>
                                </div>
                            </Card>
                        ))}
                    </div>
                    </>
                    )}
                </Container>
            </div>
        </Layout>
    );
}
