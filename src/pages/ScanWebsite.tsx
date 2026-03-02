import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Select from '@components/ui/Select';
import Button from '@components/ui/Button';
import ScrollReveal from '@components/ui/ScrollReveal';
import { isValidUrl } from '@utils/validation';
import { scanAPI } from '@/services/api';
import { AxiosError } from 'axios';

export default function ScanWebsite() {
    const navigate = useNavigate();
    const [scanType, setScanType] = useState<'url' | 'file'>('url');
    const [formData, setFormData] = useState({
        url: '',
        scanDepth: 'medium',
        includeSubdomains: false,
        checkSsl: true,
        followRedirects: true,
    });
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [errors, setErrors] = useState({ url: '' });
    const [apiError, setApiError] = useState('');
    const [isScanning, setIsScanning] = useState(false);

    const scanDepthOptions = [
        { value: 'shallow', label: 'Shallow (Fast - 5-10 minutes)' },
        { value: 'medium', label: 'Medium (Recommended - 15-30 minutes)' },
        { value: 'deep', label: 'Deep (Thorough - 45-60 minutes)' },
    ];

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
        const { name, value, type } = e.target;
        const checked = (e.target as HTMLInputElement).checked;

        setFormData((prev) => ({
            ...prev,
            [name]: type === 'checkbox' ? checked : value,
        }));

        if (errors.url && name === 'url') {
            setErrors({ url: '' });
        }
    };

    const validateForm = (): boolean => {
        if (!formData.url.trim()) {
            setErrors({ url: 'Website URL is required' });
            return false;
        }

        if (!isValidUrl(formData.url)) {
            setErrors({ url: 'Please enter a valid URL (e.g., https://example.com)' });
            return false;
        }

        setErrors({ url: '' });
        return true;
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) return;

        setIsScanning(true);
        setApiError('');

        try {
            const { data } = await scanAPI.scanWebsite({
                url: formData.url,
                scanDepth: formData.scanDepth,
                includeSubdomains: formData.includeSubdomains,
                checkSsl: formData.checkSsl,
                followRedirects: formData.followRedirects,
            });
            navigate(`/scan/results/${data.id}`);
        } catch (err) {
            const axiosErr = err as AxiosError<{ detail?: string; message?: string }>;
            setApiError(
                axiosErr.response?.data?.detail ||
                axiosErr.response?.data?.message ||
                'Failed to start scan. Please try again.',
            );
            setIsScanning(false);
        }
    };

    const handleFileSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedFile) {
            setApiError('Please select a file to scan');
            return;
        }
        setIsScanning(true);
        setApiError('');
        try {
            const fd = new FormData();
            fd.append('file', selectedFile);
            const { data } = await scanAPI.scanFile(fd);
            navigate(`/scan/results/${data.id}`);
        } catch (err) {
            const axiosErr = err as AxiosError<{ detail?: string; message?: string }>;
            setApiError(
                axiosErr.response?.data?.detail ||
                axiosErr.response?.data?.message ||
                'Failed to scan file. Please try again.',
            );
            setIsScanning(false);
        }
    };

    const vulnerabilityChecks = [
        'SQL Injection',
        'Cross-Site Scripting (XSS)',
        'CSRF Attacks',
        'Broken Authentication',
        'Security Misconfiguration',
        'Sensitive Data Exposure',
        'Broken Access Control',
        'XML External Entities (XXE)',
        'Insecure Deserialization',
        'Known Vulnerable Components',
        'Insufficient Logging',
        'Server-Side Request Forgery (SSRF)',
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <ScrollReveal>
                    <div className="mb-8">
                        <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                            Scan Website for Vulnerabilities
                        </h1>
                        <p className="text-lg text-text-secondary">
                            Comprehensive security analysis powered by AI
                        </p>
                    </div>
                    </ScrollReveal>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Scan Form */}
                        <Card className="lg:col-span-2 p-8">
                            {/* Tab Switcher */}
                            <div className="flex gap-1 p-1 rounded-lg bg-bg-secondary mb-6">
                                <button
                                    type="button"
                                    onClick={() => { setScanType('url'); setApiError(''); }}
                                    className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-4 rounded-md text-sm font-medium transition-colors ${scanType === 'url' ? 'bg-accent-green text-bg-primary' : 'text-text-secondary hover:text-text-primary'}`}
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>
                                    URL Scan
                                </button>
                                <button
                                    type="button"
                                    onClick={() => { setScanType('file'); setApiError(''); }}
                                    className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-4 rounded-md text-sm font-medium transition-colors ${scanType === 'file' ? 'bg-accent-green text-bg-primary' : 'text-text-secondary hover:text-text-primary'}`}
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                                    File Scan
                                </button>
                            </div>

                            {scanType === 'url' ? (
                            <form onSubmit={handleSubmit} className="space-y-6">
                                {/* API Error */}
                                {apiError && (
                                    <div className="p-3 rounded-lg bg-status-critical/10 border border-status-critical/20 text-status-critical text-sm">
                                        {apiError}
                                    </div>
                                )}

                                {/* URL Input */}
                                <Input
                                    type="url"
                                    name="url"
                                    label="Target URL"
                                    placeholder="https://example.com"
                                    value={formData.url}
                                    onChange={handleChange}
                                    error={errors.url}
                                    helperText="Enter the full URL including http:// or https://"
                                    leftIcon={
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                                        </svg>
                                    }
                                />

                                {/* Scan Depth */}
                                <Select
                                    name="scanDepth"
                                    label="Scan Depth"
                                    options={scanDepthOptions}
                                    value={formData.scanDepth}
                                    onChange={handleChange}
                                    helperText="Deeper scans provide more comprehensive results but take longer"
                                />

                                {/* Options */}
                                <div className="space-y-3">
                                    <label className="text-sm font-medium text-text-secondary block mb-3">
                                        Scan Options
                                    </label>

                                    <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg bg-bg-secondary hover:bg-bg-hover transition-colors">
                                        <input
                                            type="checkbox"
                                            name="includeSubdomains"
                                            checked={formData.includeSubdomains}
                                            onChange={handleChange}
                                            className="w-4 h-4 rounded border-border-primary bg-bg-primary text-accent-green focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-bg-primary cursor-pointer"
                                        />
                                        <div className="flex-1">
                                            <span className="text-sm font-medium text-text-primary">
                                                Include Subdomains
                                            </span>
                                            <p className="text-xs text-text-tertiary mt-0.5">
                                                Scan all subdomains under the main domain
                                            </p>
                                        </div>
                                    </label>

                                    <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg bg-bg-secondary hover:bg-bg-hover transition-colors">
                                        <input
                                            type="checkbox"
                                            name="checkSsl"
                                            checked={formData.checkSsl}
                                            onChange={handleChange}
                                            className="w-4 h-4 rounded border-border-primary bg-bg-primary text-accent-green focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-bg-primary cursor-pointer"
                                        />
                                        <div className="flex-1">
                                            <span className="text-sm font-medium text-text-primary">
                                                Check SSL/TLS Configuration
                                            </span>
                                            <p className="text-xs text-text-tertiary mt-0.5">
                                                Verify certificate validity and configuration
                                            </p>
                                        </div>
                                    </label>

                                    <label className="flex items-center gap-3 cursor-pointer p-3 rounded-lg bg-bg-secondary hover:bg-bg-hover transition-colors">
                                        <input
                                            type="checkbox"
                                            name="followRedirects"
                                            checked={formData.followRedirects}
                                            onChange={handleChange}
                                            className="w-4 h-4 rounded border-border-primary bg-bg-primary text-accent-green focus:ring-2 focus:ring-accent-green focus:ring-offset-2 focus:ring-offset-bg-primary cursor-pointer"
                                        />
                                        <div className="flex-1">
                                            <span className="text-sm font-medium text-text-primary">
                                                Follow Redirects
                                            </span>
                                            <p className="text-xs text-text-tertiary mt-0.5">
                                                Automatically follow HTTP redirects during scan
                                            </p>
                                        </div>
                                    </label>
                                </div>

                                {/* Submit Button */}
                                <div className="pt-4">
                                    <Button
                                        type="submit"
                                        variant="primary"
                                        size="lg"
                                        className="w-full"
                                        isLoading={isScanning}
                                    >
                                        {isScanning ? (
                                            'Initiating Scan...'
                                        ) : (
                                            <>
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                                </svg>
                                                Start Security Scan
                                            </>
                                        )}
                                    </Button>
                                </div>
                            </form>
                            ) : (
                            <form onSubmit={handleFileSubmit} className="space-y-6">
                                {/* API Error */}
                                {apiError && (
                                    <div className="p-3 rounded-lg bg-status-critical/10 border border-status-critical/20 text-status-critical text-sm">
                                        {apiError}
                                    </div>
                                )}

                                {/* File Upload */}
                                <div>
                                    <label className="text-sm font-medium text-text-secondary block mb-3">Upload File</label>
                                    <div
                                        className="border-2 border-dashed border-border-primary rounded-lg p-8 text-center hover:border-accent-green/50 transition-colors cursor-pointer"
                                        onClick={() => document.getElementById('file-input')?.click()}
                                        onDragOver={(e) => e.preventDefault()}
                                        onDrop={(e) => {
                                            e.preventDefault();
                                            const file = e.dataTransfer.files[0];
                                            if (file) setSelectedFile(file);
                                        }}
                                    >
                                        <input
                                            id="file-input"
                                            type="file"
                                            className="hidden"
                                            accept=".html,.htm,.js,.ts,.jsx,.tsx,.php,.py,.rb,.java,.cs,.go,.rs,.xml,.json,.yaml,.yml"
                                            onChange={(e) => {
                                                const file = e.target.files?.[0];
                                                if (file) setSelectedFile(file);
                                            }}
                                        />
                                        {selectedFile ? (
                                            <div>
                                                <svg className="w-10 h-10 mx-auto text-accent-green mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                </svg>
                                                <p className="text-sm font-medium text-text-primary">{selectedFile.name}</p>
                                                <p className="text-xs text-text-tertiary mt-1">{(selectedFile.size / 1024).toFixed(1)} KB</p>
                                                <button
                                                    type="button"
                                                    className="text-xs text-accent-red mt-2 hover:underline"
                                                    onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                                                >
                                                    Remove
                                                </button>
                                            </div>
                                        ) : (
                                            <div>
                                                <svg className="w-10 h-10 mx-auto text-text-tertiary mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                                                </svg>
                                                <p className="text-sm text-text-secondary">Drag and drop a file here, or click to browse</p>
                                                <p className="text-xs text-text-tertiary mt-1">Supports HTML, JS, TS, PHP, Python, and more</p>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Submit Button */}
                                <div className="pt-4">
                                    <Button
                                        type="submit"
                                        variant="primary"
                                        size="lg"
                                        className="w-full"
                                        isLoading={isScanning}
                                        disabled={!selectedFile}
                                    >
                                        {isScanning ? 'Scanning File...' : (
                                            <>
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                                </svg>
                                                Scan File
                                            </>
                                        )}
                                    </Button>
                                </div>
                            </form>
                            )}
                        </Card>

                        {/* Info Sidebar */}
                        <div className="space-y-6">
                            {/* What We Scan */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    What We Scan For
                                </h3>
                                <div className="space-y-2">
                                    {vulnerabilityChecks.map((check, index) => (
                                        <div key={index} className="flex items-center gap-2 text-sm text-text-secondary">
                                            <svg className="w-4 h-4 text-accent-green flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                            </svg>
                                            <span>{check}</span>
                                        </div>
                                    ))}
                                </div>
                            </Card>

                            {/* Security Standards */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    Compliance Standards
                                </h3>
                                <div className="space-y-3">
                                    <div className="flex items-center gap-3 p-3 rounded-lg bg-bg-secondary">
                                        <div className="w-10 h-10 rounded bg-accent-green/10 flex items-center justify-center text-accent-green text-xs font-bold">
                                            OWASP
                                        </div>
                                        <div>
                                            <div className="text-sm font-medium text-text-primary">OWASP Top 10</div>
                                            <div className="text-xs text-text-tertiary">Web Security</div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-3 p-3 rounded-lg bg-bg-secondary">
                                        <div className="w-10 h-10 rounded bg-accent-blue/10 flex items-center justify-center text-accent-blue text-xs font-bold">
                                            CWE
                                        </div>
                                        <div>
                                            <div className="text-sm font-medium text-text-primary">CWE Top 25</div>
                                            <div className="text-xs text-text-tertiary">Common Weaknesses</div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-3 p-3 rounded-lg bg-bg-secondary">
                                        <div className="w-10 h-10 rounded bg-accent-green/10 flex items-center justify-center text-accent-green text-xs font-bold">
                                            PCI
                                        </div>
                                        <div>
                                            <div className="text-sm font-medium text-text-primary">PCI DSS</div>
                                            <div className="text-xs text-text-tertiary">Payment Security</div>
                                        </div>
                                    </div>
                                </div>
                            </Card>

                            {/* Help */}
                            <Card className="p-6 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                                <div className="flex items-start gap-3">
                                    <div className="w-10 h-10 rounded-lg bg-accent-green/20 flex items-center justify-center text-accent-green flex-shrink-0">
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </div>
                                    <div>
                                        <h4 className="text-sm font-semibold text-text-primary mb-1">
                                            Need Help?
                                        </h4>
                                        <p className="text-xs text-text-tertiary mb-3">
                                            Check our documentation for scanning best practices
                                        </p>
                                        <Link
                                            to="/docs"
                                            className="text-sm text-accent-green hover:text-accent-green-hover font-medium"
                                        >
                                            View Documentation →
                                        </Link>
                                    </div>
                                </div>
                            </Card>
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
