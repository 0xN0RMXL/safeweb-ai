import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Select from '@components/ui/Select';
import Button from '@components/ui/Button';
import { isValidUrl } from '@utils/validation';

export default function ScanWebsite() {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        url: '',
        scanDepth: 'medium',
        includeSubdomains: false,
        checkSsl: true,
        followRedirects: true,
    });
    const [errors, setErrors] = useState({ url: '' });
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

        // Simulate scan initiation
        setTimeout(() => {
            setIsScanning(false);
            // Navigate to results page
            navigate('/results/mock-scan-id');
        }, 2000);
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
                    <div className="mb-8">
                        <h1 className="text-3xl md:text-4xl font-heading font-bold text-text-primary mb-3">
                            Scan Website for Vulnerabilities
                        </h1>
                        <p className="text-lg text-text-secondary">
                            Comprehensive security analysis powered by AI
                        </p>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        {/* Scan Form */}
                        <Card className="lg:col-span-2 p-8">
                            <form onSubmit={handleSubmit} className="space-y-6">
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
                                        <a
                                            href="/docs"
                                            className="text-sm text-accent-green hover:text-accent-green-hover font-medium"
                                        >
                                            View Documentation →
                                        </a>
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
