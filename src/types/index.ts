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
    severity: 'critical' | 'high' | 'medium' | 'low';
    category: string;
    description: string;
    impact: string;
    remediation: string;
    cwe?: string;
    cvss?: number;
    affectedUrl?: string;
    evidenceCode?: string;
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
    };
    score: number; // 0-100, where 100 is most secure
    scanOptions?: {
        depth?: number;
        includeSubdomains?: boolean;
        checkSsl?: boolean;
    };
}

export interface ScanHistory {
    scans: ScanResult[];
    totalScans: number;
    lastScan?: string;
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
