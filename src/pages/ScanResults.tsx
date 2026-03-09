import { useState, useEffect, useRef, useCallback } from 'react';
import { useSSE } from '@/hooks/useSSE';
import { useParams, Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import ReconTab from '@components/scan/ReconTab';
import TesterBreakdownTab from '@components/scan/TesterBreakdownTab';
import AttackChainTab from '@components/scan/AttackChainTab';
import MLAnalysisTab from '@components/scan/MLAnalysisTab';
import { formatDateTime } from '@utils/date';
import { scanAPI } from '@/services/api';
import type { ScanResult, Vulnerability } from '@/types';

type Tab = 'overview' | 'findings' | 'recon' | 'testers' | 'chains' | 'ml';

const TABS: { id: Tab; label: string }[] = [
    { id: 'overview',  label: 'Overview' },
    { id: 'findings',  label: 'Findings' },
    { id: 'recon',     label: 'Recon' },
    { id: 'testers',   label: 'Tester Breakdown' },
    { id: 'chains',    label: 'Attack Chains' },
    { id: 'ml',        label: 'ML Analysis' },
];

export default function ScanResults() {
    const { id } = useParams();
    const [activeTab, setActiveTab] = useState<Tab>('overview');
    const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
    const [isLoading, setIsLoading] = useState(true);
    const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
    const statusRef = useRef('scanning');
    const [sseUrl, setSseUrl] = useState<string | null>(null);

    const [scan, setScan] = useState<ScanResult>({
        id: id || '',
        target: '',
        type: 'website',
        status: 'scanning',
        startTime: new Date().toISOString(),
        score: 0,
        vulnerabilities: [],
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    });

    useEffect(() => {
        if (!id) return;

        const fetchResults = () => {
            scanAPI.getResults(id).then(({ data }) => {
                const vuln: Vulnerability[] = (data.vulnerabilities ?? []).map((v: Record<string, unknown>) => ({
                    id: v.id,
                    name: v.name ?? v.title,
                    severity: v.severity,
                    category: v.category,
                    cwe: v.cwe ?? v.cwe_id ?? '',
                    cvss: v.cvss ?? 0,
                    affectedUrl: (v.affectedUrl ?? v.affected_url ?? v.url ?? '') as string,
                    evidenceCode: v.evidence as string ?? '',
                    description: v.description as string ?? '',
                    impact: v.impact as string ?? '',
                    remediation: v.remediation as string ?? '',
                    verified: (v.verified ?? false) as boolean,
                    isFalsePositive: (v.isFalsePositive ?? v.is_false_positive ?? false) as boolean,
                    falsePositiveScore: (v.falsePositiveScore ?? v.false_positive_score) as number | undefined,
                    attackChain: (v.attackChain ?? v.attack_chain) as string | undefined,
                    oobCallback: (v.oobCallback ?? v.oob_callback) as string | undefined,
                    exploitData: (v.exploitData ?? v.exploit_data) as Vulnerability['exploitData'] | undefined,
                    toolName: (v.toolName ?? v.tool_name) as string | undefined,
                }));

                setScan({
                    id: data.id,
                    target: data.target,
                    type: data.type ?? 'website',
                    status: data.status,
                    startTime: data.startTime ?? data.start_time ?? data.started_at ?? data.created_at,
                    endTime: data.endTime ?? data.end_time ?? data.completed_at ?? undefined,
                    duration: data.duration ?? 0,
                    score: data.score ?? 0,
                    vulnerabilities: vuln,
                    summary: data.summary ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                    scanOptions: data.scanOptions ?? data.scan_options,
                    progress: data.progress,
                    currentPhase: data.currentPhase ?? data.current_phase,
                    totalRequests: data.totalRequests ?? data.total_requests,
                    pagesCrawled: data.pagesCrawled ?? data.pages_crawled,
                    mode: data.mode,
                    reconData: data.reconData ?? data.recon_data,
                    testerResults: data.testerResults ?? data.tester_results,
                    mlResult: data.mlResult ?? data.ml_result,
                });

                statusRef.current = data.status;
                if (data.status === 'completed' || data.status === 'failed') {
                    setIsLoading(false);
                }
            }).catch(() => setIsLoading(false));
        };

        fetchResults();

        // Fall back to polling only if SSE is not available
        const interval = setInterval(() => {
            if (statusRef.current === 'completed' || statusRef.current === 'failed') {
                clearInterval(interval);
                return;
            }
            fetchResults();
        }, 8000);
        pollRef.current = interval;

        // Activate SSE stream for real-time updates
        const streamUrl = scanAPI.getStreamUrl(id);
        setSseUrl(streamUrl);

        return () => {
            clearInterval(interval);
            setSseUrl(null);
        };
    }, [id]);

    useEffect(() => {
        if ((scan.status === 'completed' || scan.status === 'failed') && pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
            setSseUrl(null);
            setIsLoading(false);
        }
    }, [scan.status]);

    const handleSseCompleted = useCallback(() => {
        if (!id) return;
        setSseUrl(null);
        if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
        scanAPI.getResults(id).then(({ data }) => {
            statusRef.current = data.status ?? 'completed';
            setScan((prev) => ({ ...prev, status: data.status ?? 'completed', score: data.score ?? prev.score }));
            setIsLoading(false);
        }).catch(() => setIsLoading(false));
    }, [id]);

    useSSE(sseUrl, {
        onCompleted: handleSseCompleted,
        onError: () => { /* SSE failed — polling fallback continues */ setSseUrl(null); },
    });

    const handleMarkFalsePositive = async (vulnId: string, current: boolean) => {
        if (!id) return;
        try {
            await scanAPI.markFalsePositive(id, vulnId, !current);
            setScan((prev) => ({
                ...prev,
                vulnerabilities: prev.vulnerabilities.map((v) =>
                    v.id === vulnId ? { ...v, isFalsePositive: !current } : v,
                ),
            }));
        } catch (e) {
            console.error('Failed to update finding:', e);
        }
    };

    const handleExport = async (format: string) => {
        if (!id) return;
        try {
            const { data } = await scanAPI.exportScan(id, format);
            if (data instanceof Blob) {
                if (data.type === 'application/json') {
                    const text = await data.text();
                    const err = JSON.parse(text);
                    alert(err.detail || 'Export failed.');
                    return;
                }
                const mimeTypes: Record<string, string> = { pdf: 'application/pdf', csv: 'text/csv' };
                const blob = new Blob([data], { type: mimeTypes[format] || data.type });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = `scan-report-${id}.${format}`; a.click();
                URL.revokeObjectURL(url);
            } else {
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = `scan-report-${id}.json`; a.click();
                URL.revokeObjectURL(url);
            }
        } catch (err) { console.error('Export failed:', err); }
    };

    const handleRescan = async () => {
        if (!id) return;
        try {
            const { data } = await scanAPI.rescan(id);
            if (data.id) { window.location.href = `/scan/results/${data.id}`; }
        } catch (err) { console.error('Rescan failed:', err); }
    };

    const getSeverityColor = (severity: string) => {
        const map: Record<string, string> = {
            critical: 'text-status-critical', high: 'text-status-high',
            medium: 'text-status-medium', low: 'text-status-low', info: 'text-text-tertiary',
        };
        return map[severity] || 'text-text-tertiary';
    };

    const filteredVulns = selectedSeverity === 'all'
        ? scan.vulnerabilities
        : scan.vulnerabilities.filter((v) => v.severity === selectedSeverity);

    // ── Scanning progress banner ─────────────────────────────────────────────
    const renderScanningBanner = () => {
        if (scan.status !== 'scanning' && scan.status !== 'pending') return null;
        return (
            <Card className="p-4 mb-6 border-accent-green/30 bg-accent-green/5">
                <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                        <div className="w-5 h-5 border-2 border-accent-green border-t-transparent rounded-full animate-spin flex-shrink-0" />
                        <span className="text-sm text-text-primary font-medium">
                            {scan.currentPhase || 'Scan in progress…'}
                        </span>
                    </div>
                    <span className="text-sm text-accent-green font-semibold">{scan.progress ?? 0}%</span>
                </div>
                {typeof scan.progress === 'number' && (
                    <div className="h-1.5 bg-bg-secondary rounded-full overflow-hidden">
                        <div className="h-full bg-accent-green rounded-full transition-all duration-500"
                            style={{ width: `${scan.progress}%` }} />
                    </div>
                )}
                <div className="flex gap-6 mt-2 text-xs text-text-tertiary">
                    {scan.totalRequests !== undefined && <span>{scan.totalRequests.toLocaleString()} requests</span>}
                    {scan.pagesCrawled !== undefined && <span>{scan.pagesCrawled.toLocaleString()} pages crawled</span>}
                </div>
            </Card>
        );
    };

    // ── Overview tab ─────────────────────────────────────────────────────────
    const renderOverview = () => (
        <div className="space-y-6">
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
                <Card className="p-6 text-center md:col-span-1">
                    <div className={`text-4xl font-bold mb-2 ${scan.score >= 70 ? 'text-accent-green' : scan.score >= 40 ? 'text-status-medium' : 'text-status-critical'}`}>
                        {scan.score}
                    </div>
                    <div className="text-xs text-text-tertiary">Security Score</div>
                </Card>
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
                    <Card key={sev} className="p-6 text-center cursor-pointer hover:bg-bg-hover transition-colors"
                        onClick={() => { setActiveTab('findings'); setSelectedSeverity(sev); }}>
                        <div className={`text-4xl font-bold mb-2 ${getSeverityColor(sev)}`}>
                            {scan.summary[sev] ?? 0}
                        </div>
                        <div className="text-xs text-text-tertiary capitalize">{sev}</div>
                    </Card>
                ))}
            </div>

            <Card className="p-6">
                <h3 className="text-lg font-semibold text-text-primary mb-4">Scan Details</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                    <div>
                        <div className="text-xs text-text-tertiary mb-1">Start Time</div>
                        <div className="text-sm text-text-primary font-mono">{formatDateTime(new Date(scan.startTime))}</div>
                    </div>
                    {scan.endTime && (
                        <div>
                            <div className="text-xs text-text-tertiary mb-1">End Time</div>
                            <div className="text-sm text-text-primary font-mono">{formatDateTime(new Date(scan.endTime))}</div>
                        </div>
                    )}
                    <div>
                        <div className="text-xs text-text-tertiary mb-1">Duration</div>
                        <div className="text-sm text-text-primary font-mono">{scan.duration ?? 0}s</div>
                    </div>
                    <div>
                        <div className="text-xs text-text-tertiary mb-1">Status</div>
                        <Badge variant={scan.status === 'completed' ? 'low' : scan.status === 'failed' ? 'critical' : 'info'} size="sm">
                            {scan.status}
                        </Badge>
                    </div>
                    {scan.mode && (
                        <div>
                            <div className="text-xs text-text-tertiary mb-1">Scan Mode</div>
                            <div className="text-sm text-text-primary capitalize">{scan.mode}</div>
                        </div>
                    )}
                    {scan.totalRequests !== undefined && (
                        <div>
                            <div className="text-xs text-text-tertiary mb-1">Total Requests</div>
                            <div className="text-sm text-text-primary">{scan.totalRequests.toLocaleString()}</div>
                        </div>
                    )}
                    {scan.pagesCrawled !== undefined && (
                        <div>
                            <div className="text-xs text-text-tertiary mb-1">Pages Crawled</div>
                            <div className="text-sm text-text-primary">{scan.pagesCrawled.toLocaleString()}</div>
                        </div>
                    )}
                </div>
            </Card>

            {scan.mlResult && (
                <Card className="p-6 border-accent-green/20">
                    <div className="flex items-center gap-4">
                        <svg className="w-8 h-8 text-accent-green flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                        </svg>
                        <div className="flex-1">
                            <div className="text-sm font-semibold text-text-primary mb-1">ML Assessment</div>
                            <div className="flex items-center gap-3">
                                <Badge variant={scan.mlResult.prediction === 'benign' ? 'low' : scan.mlResult.prediction === 'malicious' ? 'critical' : 'high'} size="sm">
                                    {scan.mlResult.prediction?.toUpperCase() ?? 'N/A'}
                                </Badge>
                                {scan.mlResult.confidence !== undefined && (
                                    <span className="text-sm text-text-secondary">{Math.round(scan.mlResult.confidence * 100)}% confidence</span>
                                )}
                            </div>
                        </div>
                        <Button variant="outline" size="sm" onClick={() => setActiveTab('ml')}>Full ML Report →</Button>
                    </div>
                </Card>
            )}

            {scan.status === 'failed' && (
                <Card className="p-6 border-status-critical/30 bg-status-critical/5">
                    <div className="flex items-start gap-3">
                        <svg className="w-6 h-6 text-status-critical flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <div>
                            <h3 className="text-lg font-semibold text-status-critical mb-1">Scan Failed</h3>
                            <p className="text-sm text-text-secondary">This scan encountered an error and could not complete. Please try running a re-scan.</p>
                        </div>
                    </div>
                </Card>
            )}
        </div>
    );

    // ── Findings tab ─────────────────────────────────────────────────────────
    const renderFindings = () => (
        <div>
            <div className="flex items-center gap-3 mb-6 flex-wrap">
                <span className="text-sm text-text-tertiary">Filter:</span>
                {['all', 'critical', 'high', 'medium', 'low', 'info'].map((sev) => (
                    <button key={sev} onClick={() => setSelectedSeverity(sev)}
                        className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${selectedSeverity === sev ? 'bg-accent-green text-bg-primary' : 'bg-bg-secondary text-text-secondary hover:bg-bg-hover'}`}>
                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                        {sev !== 'all' && ` (${scan.summary[sev as keyof typeof scan.summary] ?? 0})`}
                    </button>
                ))}
            </div>

            {filteredVulns.length === 0 && scan.status === 'completed' ? (
                <Card className="p-12 text-center">
                    <svg className="w-16 h-16 mx-auto text-status-low mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 className="text-xl font-heading font-semibold text-text-primary mb-2">No Vulnerabilities Found</h3>
                    <p className="text-text-secondary">No security vulnerabilities were detected in this scan.</p>
                </Card>
            ) : (
                <div className="space-y-4">
                    {filteredVulns.map((vuln) => (
                        <Card key={vuln.id} className={`p-6 hover:shadow-card-hover transition-all duration-300 ${vuln.isFalsePositive ? 'opacity-60' : ''}`}>
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex-1">
                                    <div className="flex items-center gap-3 mb-2 flex-wrap">
                                        <h3 className="text-lg font-heading font-semibold text-text-primary">{vuln.name}</h3>
                                        <Badge variant={vuln.severity}>{vuln.severity.toUpperCase()}</Badge>
                                        {vuln.verified && <Badge variant="low" size="sm">✓ Verified</Badge>}
                                        {vuln.isFalsePositive && <Badge variant="info" size="sm">False Positive</Badge>}
                                        {vuln.toolName && <Badge variant="info" size="sm">🔧 {vuln.toolName}</Badge>}
                                        {vuln.attackChain && <Badge variant="high" size="sm">⛓ Chain: {vuln.attackChain}</Badge>}
                                        {vuln.exploitData?.exploit?.success && <Badge variant="critical" size="sm">💥 Exploited</Badge>}
                                        {vuln.exploitData?.report && <Badge variant="info" size="sm">📄 BB Report</Badge>}
                                    </div>
                                    <div className="flex items-center gap-4 text-sm text-text-tertiary flex-wrap">
                                        {vuln.cwe && <span className="font-mono">{vuln.cwe}</span>}
                                        {vuln.cvss !== undefined && vuln.cvss > 0 && <><span>•</span><span>CVSS {vuln.cvss}</span></>}
                                        {vuln.category && <><span>•</span><span>{vuln.category}</span></>}
                                        {vuln.falsePositiveScore !== undefined && (
                                            <><span>•</span><span>FP Score: {Math.round(vuln.falsePositiveScore * 100)}%</span></>
                                        )}
                                    </div>
                                </div>
                                <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                                    <button
                                        onClick={() => {
                                            const msg = `Tell me about this vulnerability: "${vuln.name}" (${vuln.severity.toUpperCase()})${vuln.cwe ? ` | ${vuln.cwe}` : ''}${vuln.affectedUrl ? ` | URL: ${vuln.affectedUrl}` : ''}${vuln.description ? `\n\n${vuln.description}` : ''}`;
                                            window.dispatchEvent(new CustomEvent('safeweb-chatbot-ask', { detail: { message: msg } }));
                                        }}
                                        className="text-xs px-2 py-1 rounded bg-accent-green/10 text-accent-green hover:bg-accent-green/20 transition-colors border border-accent-green/30"
                                        title="Ask AI about this finding"
                                    >
                                        Ask AI
                                    </button>
                                    <button onClick={() => handleMarkFalsePositive(vuln.id, vuln.isFalsePositive ?? false)}
                                        className="text-xs px-2 py-1 rounded bg-bg-secondary text-text-tertiary hover:bg-bg-hover transition-colors">
                                        {vuln.isFalsePositive ? '↩ Un-FP' : '⚑ FP'}
                                    </button>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div>
                                    <h4 className="text-sm font-semibold text-text-primary mb-2">Description</h4>
                                    <p className="text-sm text-text-secondary leading-relaxed">{vuln.description}</p>
                                </div>
                                {vuln.affectedUrl && (
                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Affected URL</h4>
                                        <code className="text-sm text-accent-green font-mono bg-bg-secondary px-3 py-1 rounded break-all">{vuln.affectedUrl}</code>
                                    </div>
                                )}
                                {vuln.impact && (
                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Impact</h4>
                                        <p className="text-sm text-text-secondary">{vuln.impact}</p>
                                    </div>
                                )}
                                {vuln.remediation && (
                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Remediation</h4>
                                        <p className="text-sm text-text-secondary">{vuln.remediation}</p>
                                    </div>
                                )}
                                {vuln.evidenceCode && (
                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-2">Evidence</h4>
                                        <pre className="text-xs font-mono bg-bg-secondary text-text-secondary p-4 rounded-lg overflow-x-auto">{vuln.evidenceCode}</pre>
                                    </div>
                                )}

                                {/* ── Exploit Proof ─────────────────────────── */}
                                {vuln.exploitData?.exploit && (
                                    <details className="group border border-border-primary rounded-lg overflow-hidden">
                                        <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer bg-bg-secondary hover:bg-bg-hover transition-colors select-none">
                                            <span className={`text-sm font-semibold ${vuln.exploitData.exploit.success ? 'text-status-critical' : 'text-text-tertiary'}`}>
                                                {vuln.exploitData.exploit.success ? '💥 Exploit Proof' : '⚠ Exploit Attempted (Failed)'}
                                            </span>
                                            <Badge variant={vuln.exploitData.exploit.success ? 'critical' : 'info'} size="sm">
                                                {vuln.exploitData.exploit.exploitType}
                                            </Badge>
                                            <svg className="w-4 h-4 ml-auto text-text-tertiary transition-transform group-open:rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                            </svg>
                                        </summary>
                                        <div className="p-4 space-y-4 border-t border-border-primary">
                                            {vuln.exploitData.exploit.poc && (
                                                <div>
                                                    <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-2">Proof of Concept</h5>
                                                    <pre className="text-xs font-mono bg-bg-primary text-accent-green p-4 rounded-lg overflow-x-auto whitespace-pre-wrap border border-border-primary">{vuln.exploitData.exploit.poc}</pre>
                                                </div>
                                            )}
                                            {vuln.exploitData.exploit.steps?.length > 0 && (
                                                <div>
                                                    <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-2">Reproduction Steps</h5>
                                                    <ol className="list-decimal list-inside space-y-1">
                                                        {vuln.exploitData.exploit.steps.map((step, i) => (
                                                            <li key={i} className="text-sm text-text-secondary">{step}</li>
                                                        ))}
                                                    </ol>
                                                </div>
                                            )}
                                            {vuln.exploitData.exploit.impactProof && (
                                                <div>
                                                    <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-2">Impact Proof</h5>
                                                    <p className="text-sm text-text-secondary bg-bg-primary p-3 rounded-lg border border-border-primary">{vuln.exploitData.exploit.impactProof}</p>
                                                </div>
                                            )}
                                            {vuln.exploitData.exploit.extractedData && (
                                                <div>
                                                    <h5 className="text-xs font-semibold text-text-tertiary uppercase tracking-wider mb-2">Extracted Data</h5>
                                                    <pre className="text-xs font-mono bg-bg-primary text-status-high p-4 rounded-lg overflow-x-auto border border-border-primary">{typeof vuln.exploitData.exploit.extractedData === 'string' ? vuln.exploitData.exploit.extractedData : JSON.stringify(vuln.exploitData.exploit.extractedData, null, 2)}</pre>
                                                </div>
                                            )}
                                        </div>
                                    </details>
                                )}

                                {/* ── Bug Bounty Report ───────────────────────── */}
                                {vuln.exploitData?.report?.markdown && (
                                    <details className="group border border-border-primary rounded-lg overflow-hidden">
                                        <summary className="flex items-center gap-3 px-4 py-3 cursor-pointer bg-bg-secondary hover:bg-bg-hover transition-colors select-none">
                                            <span className="text-sm font-semibold text-text-primary">📄 Bug Bounty Report</span>
                                            {vuln.exploitData.report.llmEnhanced && (
                                                <Badge variant="low" size="sm">AI-Enhanced</Badge>
                                            )}
                                            <svg className="w-4 h-4 ml-auto text-text-tertiary transition-transform group-open:rotate-180" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                            </svg>
                                        </summary>
                                        <div className="p-4 border-t border-border-primary">
                                            <pre className="text-sm font-mono bg-bg-primary text-text-secondary p-4 rounded-lg overflow-x-auto whitespace-pre-wrap border border-border-primary leading-relaxed">{vuln.exploitData.report.markdown}</pre>
                                        </div>
                                    </details>
                                )}
                            </div>
                        </Card>
                    ))}
                </div>
            )}
        </div>
    );

    if (isLoading && !scan.target) {
        return (
            <Layout>
                <div className="flex items-center justify-center py-32">
                    <div className="w-8 h-8 border-2 border-accent-green border-t-transparent rounded-full animate-spin" />
                    <span className="ml-3 text-text-secondary">Loading scan results…</span>
                </div>
            </Layout>
        );
    }

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex flex-col md:flex-row md:items-start md:justify-between mb-8">
                        <div>
                            <Link to="/history" className="text-sm text-accent-green hover:text-accent-green-hover mb-2 inline-flex items-center gap-1">
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                                </svg>
                                Back to History
                            </Link>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-1">Scan Results</h1>
                            <p className="text-text-secondary font-mono text-sm">{scan.target}</p>
                        </div>
                        <div className="flex items-center gap-3 mt-4 md:mt-0 flex-wrap">
                            {scan.status === 'completed' && (
                                <>
                                    <Button variant="outline" size="sm" onClick={() => handleExport('json')}>Export JSON</Button>
                                    <Button variant="outline" size="sm" onClick={() => handleExport('pdf')}>Export PDF</Button>
                                    <Button variant="outline" size="sm" onClick={() => handleExport('csv')}>Export CSV</Button>
                                </>
                            )}
                            <Button variant="primary" size="sm" onClick={handleRescan}>
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                </svg>
                                Re-scan
                            </Button>
                        </div>
                    </div>

                    {renderScanningBanner()}

                    {/* Tab navigation */}
                    <div className="flex items-center gap-1 border-b border-border-primary mb-8 overflow-x-auto">
                        {TABS.map((tab) => {
                            const counts: Partial<Record<Tab, number>> = {
                                findings: scan.summary.total,
                                testers: scan.testerResults?.length,
                                chains: scan.vulnerabilities.filter((v) => v.attackChain).length,
                            };
                            const count = counts[tab.id];
                            return (
                                <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                                    className={`relative px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors ${activeTab === tab.id ? 'text-accent-green border-b-2 border-accent-green' : 'text-text-secondary hover:text-text-primary'}`}>
                                    {tab.label}
                                    {count !== undefined && count > 0 && (
                                        <span className="ml-2 px-1.5 py-0.5 text-xs bg-accent-green/15 text-accent-green rounded-full">{count}</span>
                                    )}
                                </button>
                            );
                        })}
                    </div>

                    {/* Tab content */}
                    {activeTab === 'overview' && renderOverview()}
                    {activeTab === 'findings' && renderFindings()}
                    {activeTab === 'recon'    && <ReconTab reconData={scan.reconData} />}
                    {activeTab === 'testers'  && <TesterBreakdownTab testerResults={scan.testerResults} totalTesters={87} />}
                    {activeTab === 'chains'   && <AttackChainTab vulnerabilities={scan.vulnerabilities} />}
                    {activeTab === 'ml'       && <MLAnalysisTab mlResult={scan.mlResult} vulnerabilities={scan.vulnerabilities} />}
                </Container>
            </div>
        </Layout>
    );
}
