export interface User {
    id: string;
    email: string;
    name: string;
    role: 'user' | 'admin';
    avatar?: string;
    createdAt: string;
    lastLogin?: string;
}

export interface ScanTarget {
    url?: string;
    file?: File;
    type: 'website' | 'file' | 'url';
}

export interface Vulnerability {
    id: string;
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    category: string;
    description: string;
    impact: string;
    remediation: string;
    cwe?: string;
    cvss?: number;
    affectedUrl?: string;
    evidenceCode?: string;
    // Tool origin — which scanner/wrapper found this vulnerability
    toolName?: string;
    // Advanced fields
    verified?: boolean;
    isFalsePositive?: boolean;
    falsePositiveScore?: number;  // 0.0 – 1.0
    attackChain?: string;         // JSON-encoded chain description
    oobCallback?: string;         // out-of-band callback URL/token
    exploitData?: {
        exploit?: {
            success: boolean;
            exploitType: string;
            extractedData: string | Record<string, unknown>;
            poc: string;
            steps: string[];
            impactProof: string;
        };
        report?: {
            markdown: string;
            structured?: Record<string, unknown>;
            llmEnhanced: boolean;
        };
    };
}

// Recon data returned by the scanner engine
// Each module returns {findings, metadata, errors, stats, issues, ...specificData}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ReconData = Record<string, any>;

// Per-tester execution summary
export interface TesterResult {
    testerName: string;
    findingsCount: number;
    durationMs: number;
    status: 'passed' | 'failed' | 'skipped';
}

// ML pipeline result
export interface MLResult {
    prediction?: 'malicious' | 'benign' | 'phishing' | 'suspicious';
    confidence?: number;  // 0.0 – 1.0
    modelUsed?: string;
    falsePositiveReduction?: number;
}

export interface ScanResult {
    id: string;
    target: string;
    type: 'website' | 'file' | 'url';
    status: 'pending' | 'scanning' | 'completed' | 'failed';
    startTime: string;
    endTime?: string;
    duration?: number;
    vulnerabilities: Vulnerability[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    score: number; // 0-100, where 100 is most secure
    scanOptions?: {
        depth?: number;
        includeSubdomains?: boolean;
        checkSsl?: boolean;
    };
    // Advanced fields
    progress?: number;       // 0–100 during active scan
    currentPhase?: string;   // e.g. "Running XSS Tester"
    totalRequests?: number;
    pagesCrawled?: number;
    mode?: 'standard' | 'continuous' | 'hunting';
    reconData?: ReconData;
    testerResults?: TesterResult[];
    mlResult?: MLResult;
}

export interface ScanHistory {
    scans: ScanResult[];
    totalScans: number;
    lastScan?: string;
}

// ── Advanced feature types ──────────────────────────────────────────

export interface ScanProfile {
    id: string;
    name: string;
    description?: string;
    testerConfig?: Record<string, boolean>;
    depthConfig?: Record<string, unknown>;
    isDefault?: boolean;
}

export interface ScheduledScan {
    id: string;
    name: string;
    target: string;
    scanConfig?: Record<string, unknown>;
    schedulePreset?: 'hourly' | 'daily' | 'weekly' | 'monthly' | 'custom';
    cronExpr?: string;
    isActive: boolean;
    lastRun?: string;
    nextRun?: string;
    notifications?: {
        onNewFindings?: boolean;
        onSslExpiry?: boolean;
        onAssetChanges?: boolean;
    };
}

export interface ScopeDefinition {
    id: string;
    name: string;
    description?: string;
    organization?: string;
    inScope: string[];        // domain/URL patterns
    outOfScope: string[];
    importFormat?: 'hackerone' | 'bugcrowd' | 'custom';
    createdAt?: string;
    updatedAt?: string;
}

export interface MultiTargetScan {
    id: string;
    name: string;
    targets: string[];
    scopeId?: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    scanDepth?: string;
    parallelLimit?: number;
    totalTargets: number;
    completedTargets: number;
    failedTargets: number;
    createdAt?: string;
}

export interface WebhookDelivery {
    id: string;
    eventType: string;
    status: 'pending' | 'delivered' | 'failed';
    httpStatus?: number;
    attemptCount: number;
    deliveredAt?: string;
    responseBody?: string;
}

export interface Webhook {
    id: string;
    url: string;
    secret?: string;
    events: string[];
    isActive: boolean;
    maxRetries?: number;
    createdAt?: string;
    deliveries?: WebhookDelivery[];
}

export interface DiscoveredAsset {
    id: string;
    url: string;
    assetType: 'domain' | 'subdomain' | 'endpoint' | 'ip' | 'other';
    techStack?: string[];
    isActive: boolean;
    isNew: boolean;
    firstSeen: string;
    lastSeen: string;
    lastScanId?: string;
}

export interface ScanComparison {
    scan1Id: string;
    scan2Id: string;
    scan1Target: string;
    scan2Target: string;
    newFindings: Vulnerability[];
    fixedFindings: Vulnerability[];
    regressedFindings: Vulnerability[];
    persistedFindings: Vulnerability[];
    scoreChange: number;
}

export interface AssetMonitorRecord {
    id: string;
    target: string;
    changeType: 'new_subdomain' | 'ssl_expiring' | 'new_port' | 'new_finding' | 'asset_gone' | 'tech_change';
    detail: string;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    acknowledged: boolean;
    detectedAt: string;
}

export interface NucleiTemplate {
    id: string;
    name: string;
    description?: string;
    category?: string;
    severity?: string;
    isActive: boolean;
    createdAt?: string;
}

export interface LearnArticle {
    id: string;
    title: string;
    slug: string;
    excerpt: string;
    content: string;
    category: string;
    tags: string[];
    author: {
        name: string;
        avatar?: string;
    };
    publishedAt: string;
    readTime: number; // in minutes
    thumbnail?: string;
}

export interface DocSection {
    id: string;
    title: string;
    slug: string;
    content: string;
    subsections?: DocSection[];
}
