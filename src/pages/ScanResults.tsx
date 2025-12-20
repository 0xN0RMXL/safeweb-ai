import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import { formatDateTime } from '@utils/date';

export default function ScanResults() {
    const { id } = useParams();
    const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

    // Mock data
    const scanData = {
        id: id || 'mock-scan-id',
        target: 'https://example.com',
        type: 'Website',
        status: 'completed',
        startTime: new Date('2025-12-20T10:30:00'),
        endTime: new Date('2025-12-20T10:45:00'),
        duration: 15,
        score: 82,
        summary: {
            total: 16,
            critical: 1,
            high: 2,
            medium: 5,
            low: 8,
        },
    };

    const vulnerabilities = [
        {
            id: '1',
            name: 'SQL Injection in Login Form',
            severity: 'critical' as const,
            category: 'Injection',
            cwe: 'CWE-89',
            cvss: 9.8,
            url: 'https://example.com/login',
            description: 'The login form is vulnerable to SQL injection attacks through the username parameter.',
            impact: 'An attacker could bypass authentication, extract sensitive data, modify database contents, or execute administrative operations.',
            remediation: 'Use parameterized queries (prepared statements) instead of concatenating user input into SQL queries. Implement input validation and sanitization.',
            evidence: `POST /login HTTP/1.1
username=' OR '1'='1
password=anything`,
        },
        {
            id: '2',
            name: 'Cross-Site Scripting (XSS) in Search',
            severity: 'high' as const,
            category: 'XSS',
            cwe: 'CWE-79',
            cvss: 7.5,
            url: 'https://example.com/search',
            description: 'Reflected XSS vulnerability in the search functionality allows execution of arbitrary JavaScript.',
            impact: 'Attackers can steal session cookies, redirect users to malicious sites, or perform actions on behalf of the victim.',
            remediation: 'Encode all user input before rendering in HTML. Implement Content Security Policy (CSP) headers. Use frameworks that auto-escape output.',
            evidence: `GET /search?q=<script>alert('XSS')</script>`,
        },
        {
            id: '3',
            name: 'Missing CSRF Token Protection',
            severity: 'high' as const,
            category: 'CSRF',
            cwe: 'CWE-352',
            cvss: 6.5,
            url: 'https://example.com/profile/update',
            description: 'State-changing operations lack CSRF token validation.',
            impact: 'Attackers can trick authenticated users into performing unwanted actions like changing email, password, or making unauthorized transactions.',
            remediation: 'Implement anti-CSRF tokens for all state-changing requests. Use SameSite cookie attribute. Verify Origin/Referer headers.',
            evidence: `POST /profile/update HTTP/1.1
No CSRF token present in form or headers`,
        },
        {
            id: '4',
            name: 'Weak SSL/TLS Configuration',
            severity: 'medium' as const,
            category: 'Security Misconfiguration',
            cwe: 'CWE-326',
            cvss: 5.3,
            url: 'https://example.com',
            description: 'Server supports outdated TLS 1.0 and weak cipher suites.',
            impact: 'Man-in-the-middle attackers could decrypt communication and steal sensitive data.',
            remediation: 'Disable TLS 1.0/1.1. Use only strong cipher suites. Implement HSTS headers.',
            evidence: `Supported: TLS 1.0, TLS 1.1, TLS 1.2
Weak ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA`,
        },
        {
            id: '5',
            name: 'Missing Security Headers',
            severity: 'medium' as const,
            category: 'Security Misconfiguration',
            cwe: 'CWE-693',
            cvss: 4.3,
            url: 'https://example.com',
            description: 'Critical security headers are missing: X-Frame-Options, X-Content-Type-Options, CSP.',
            impact: 'Increases risk of clickjacking, MIME-sniffing attacks, and XSS exploitation.',
            remediation: 'Add security headers: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Content-Security-Policy, Strict-Transport-Security.',
            evidence: `Missing headers:
- X-Frame-Options
- X-Content-Type-Options
- Content-Security-Policy`,
        },
        {
            id: '6',
            name: 'Directory Listing Enabled',
            severity: 'low' as const,
            category: 'Information Disclosure',
            cwe: 'CWE-548',
            cvss: 3.7,
            url: 'https://example.com/assets/',
            description: 'Directory listing is enabled on /assets/ endpoint.',
            impact: 'Attackers can enumerate files and potentially discover sensitive information or backup files.',
            remediation: 'Disable directory listing in web server configuration. Use index files in all directories.',
            evidence: `GET /assets/ returns directory listing with 23 files`,
        },
    ];

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
                            <Button variant="outline" size="sm">
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                </svg>
                                Export PDF
                            </Button>
                            <Button variant="primary" size="sm">
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
                                <Badge variant="low" size="sm">Completed</Badge>
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

                    {/* Vulnerabilities List */}
                    <div className="space-y-4">
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
                </Container>
            </div>
        </Layout>
    );
}
