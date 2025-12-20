import { useState } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';

export default function Documentation() {
    const [searchQuery, setSearchQuery] = useState('');

    const sections = [
        {
            id: 'getting-started',
            title: 'Getting Started',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
            ),
            items: [
                'Introduction',
                'Quick Start Guide',
                'Authentication',
                'Making Your First Scan',
            ],
        },
        {
            id: 'api-reference',
            title: 'API Reference',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
            ),
            items: [
                'Authentication Endpoints',
                'Scan Endpoints',
                'Results Endpoints',
                'Webhook Configuration',
            ],
        },
        {
            id: 'integration',
            title: 'Integration Guides',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
                </svg>
            ),
            items: [
                'GitHub Actions',
                'GitLab CI/CD',
                'Jenkins Pipeline',
                'Docker Integration',
            ],
        },
        {
            id: 'security',
            title: 'Security',
            icon: (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
            ),
            items: [
                'API Key Management',
                'Rate Limiting',
                'IP Whitelisting',
                'Security Best Practices',
            ],
        },
    ];

    const codeExamples = [
        {
            title: 'Initialize a Scan',
            language: 'bash',
            code: `curl -X POST https://api.safeweb.ai/v1/scan \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "target": "https://example.com",
    "scan_depth": "medium",
    "options": {
      "include_subdomains": true,
      "check_ssl": true
    }
  }'`,
        },
        {
            title: 'Get Scan Results',
            language: 'bash',
            code: `curl -X GET https://api.safeweb.ai/v1/scan/{scan_id} \\
  -H "Authorization: Bearer YOUR_API_KEY"`,
        },
        {
            title: 'List All Scans',
            language: 'bash',
            code: `curl -X GET https://api.safeweb.ai/v1/scans \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -G -d "status=completed" -d "limit=10"`,
        },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="text-center mb-12">
                        <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                            Documentation
                        </h1>
                        <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                            Complete API reference and integration guides
                        </p>
                    </div>

                    {/* Search */}
                    <div className="max-w-2xl mx-auto mb-12">
                        <Input
                            type="text"
                            placeholder="Search documentation..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            leftIcon={
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                </svg>
                            }
                        />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-12">
                        {/* Sidebar */}
                        <div className="lg:col-span-1">
                            <Card className="p-6 sticky top-24">
                                <h3 className="text-sm font-semibold text-text-primary mb-4">Quick Navigation</h3>
                                <nav className="space-y-2">
                                    {sections.map((section) => (
                                        <a
                                            key={section.id}
                                            href={`#${section.id}`}
                                            className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-text-secondary hover:text-accent-green hover:bg-bg-hover transition-colors"
                                        >
                                            <span className="text-accent-green">{section.icon}</span>
                                            {section.title}
                                        </a>
                                    ))}
                                </nav>
                            </Card>
                        </div>

                        {/* Content */}
                        <div className="lg:col-span-3 space-y-8">
                            {/* Sections */}
                            {sections.map((section) => (
                                <Card key={section.id} id={section.id} className="p-8">
                                    <div className="flex items-center gap-3 mb-6">
                                        <div className="w-12 h-12 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green">
                                            {section.icon}
                                        </div>
                                        <h2 className="text-2xl font-heading font-bold text-text-primary">
                                            {section.title}
                                        </h2>
                                    </div>
                                    <div className="space-y-3">
                                        {section.items.map((item, index) => (
                                            <a
                                                key={index}
                                                href={`#${section.id}-${index}`}
                                                className="block p-4 rounded-lg bg-bg-secondary hover:bg-bg-hover transition-colors group"
                                            >
                                                <div className="flex items-center justify-between">
                                                    <span className="text-sm font-medium text-text-primary group-hover:text-accent-green transition-colors">
                                                        {item}
                                                    </span>
                                                    <svg className="w-5 h-5 text-text-tertiary group-hover:text-accent-green transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                                    </svg>
                                                </div>
                                            </a>
                                        ))}
                                    </div>
                                </Card>
                            ))}

                            {/* Code Examples */}
                            <Card className="p-8">
                                <h2 className="text-2xl font-heading font-bold text-text-primary mb-6">
                                    Quick Start Examples
                                </h2>
                                <div className="space-y-6">
                                    {codeExamples.map((example, index) => (
                                        <div key={index}>
                                            <div className="flex items-center justify-between mb-3">
                                                <h3 className="text-lg font-semibold text-text-primary">
                                                    {example.title}
                                                </h3>
                                                <button className="px-3 py-1.5 rounded-lg bg-bg-secondary text-sm text-text-secondary hover:text-accent-green transition-colors">
                                                    Copy
                                                </button>
                                            </div>
                                            <pre className="bg-bg-primary p-4 rounded-lg overflow-x-auto border border-border-primary">
                                                <code className="text-sm text-accent-green font-mono">{example.code}</code>
                                            </pre>
                                        </div>
                                    ))}
                                </div>
                            </Card>

                            {/* Support */}
                            <Card className="p-8 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                                <h3 className="text-xl font-heading font-bold text-text-primary mb-3">
                                    Need Help?
                                </h3>
                                <p className="text-text-secondary mb-6">
                                    Can't find what you're looking for? Our support team is here to help.
                                </p>
                                <div className="flex flex-wrap gap-3">
                                    <a
                                        href="/contact"
                                        className="px-6 py-3 rounded-lg bg-accent-green text-bg-primary font-medium hover:bg-accent-green-hover transition-colors"
                                    >
                                        Contact Support
                                    </a>
                                    <a
                                        href="https://github.com"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="px-6 py-3 rounded-lg bg-bg-secondary text-text-primary border border-border-primary font-medium hover:bg-bg-hover transition-colors"
                                    >
                                        View on GitHub
                                    </a>
                                </div>
                            </Card>
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
