import { useState } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import Select from '@components/ui/Select';

export default function AdminScans() {
    const [searchQuery, setSearchQuery] = useState('');
    const [filterStatus, setFilterStatus] = useState('all');

    const scans = [
        { id: 1, url: 'https://example.com', user: 'john@example.com', status: 'completed', vulnerabilities: 12, severity: 'high', started: '2024-03-20 10:30', duration: '2m 15s' },
        { id: 2, url: 'https://testsite.io', user: 'jane@example.com', status: 'running', vulnerabilities: 0, severity: '-', started: '2024-03-20 11:45', duration: '-' },
        { id: 3, url: 'https://myapp.com', user: 'mike@example.com', status: 'completed', vulnerabilities: 3, severity: 'low', started: '2024-03-20 09:15', duration: '1m 45s' },
        { id: 4, url: 'https://webapp.net', user: 'sarah@example.com', status: 'failed', vulnerabilities: 0, severity: '-', started: '2024-03-20 08:00', duration: '45s' },
        { id: 5, url: 'https://shop.com', user: 'tom@example.com', status: 'completed', vulnerabilities: 25, severity: 'critical', started: '2024-03-19 16:20', duration: '3m 30s' },
        { id: 6, url: 'https://blog.dev', user: 'emily@example.com', status: 'queued', vulnerabilities: 0, severity: '-', started: '-', duration: '-' },
        { id: 7, url: 'https://api.service.io', user: 'david@example.com', status: 'completed', vulnerabilities: 8, severity: 'medium', started: '2024-03-19 14:10', duration: '2m 05s' },
        { id: 8, url: 'https://portal.app', user: 'lisa@example.com', status: 'running', vulnerabilities: 0, severity: '-', started: '2024-03-20 11:50', duration: '-' },
    ];

    const statusOptions = [
        { value: 'all', label: 'All Status' },
        { value: 'running', label: 'Running' },
        { value: 'completed', label: 'Completed' },
        { value: 'failed', label: 'Failed' },
        { value: 'queued', label: 'Queued' },
    ];

    const stats = [
        { label: 'Total Scans Today', value: '143', change: '+12' },
        { label: 'Currently Running', value: '8', change: '+2' },
        { label: 'Failed Today', value: '5', change: '-3' },
        { label: 'Avg Duration', value: '2m 18s', change: '-15s' },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                Scan Monitoring
                            </h1>
                            <p className="text-text-secondary">Monitor all security scans across the platform</p>
                        </div>
                        <div className="flex items-center gap-3">
                            <Button variant="outline" size="sm">
                                Export Report
                            </Button>
                            <Button variant="primary" size="sm">
                                Refresh
                            </Button>
                        </div>
                    </div>

                    {/* Stats */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                        {stats.map((stat, index) => (
                            <Card key={index} className="p-6">
                                <div className="text-sm text-text-tertiary mb-2">{stat.label}</div>
                                <div className="flex items-end justify-between">
                                    <div className="text-3xl font-bold text-text-primary">{stat.value}</div>
                                    <span className="text-sm text-accent-green">{stat.change}</span>
                                </div>
                            </Card>
                        ))}
                    </div>

                    {/* Filters */}
                    <Card className="p-6 mb-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <Input
                                type="text"
                                placeholder="Search by URL or user email..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                leftIcon={
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                    </svg>
                                }
                            />
                            <Select
                                options={statusOptions}
                                value={filterStatus}
                                onChange={(e) => setFilterStatus(e.target.value)}
                            />
                        </div>
                    </Card>

                    {/* Scans Table */}
                    <Card className="overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="bg-bg-secondary">
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">ID</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Target URL</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">User</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Status</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Vulnerabilities</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Severity</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Started</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Duration</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {scans.map((scan) => (
                                        <tr key={scan.id} className="border-t border-border-primary hover:bg-bg-secondary/50">
                                            <td className="py-4 px-6 text-text-secondary">#{scan.id}</td>
                                            <td className="py-4 px-6">
                                                <div className="font-medium text-text-primary">{scan.url}</div>
                                            </td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{scan.user}</td>
                                            <td className="py-4 px-6">
                                                <Badge
                                                    variant={
                                                        scan.status === 'completed'
                                                            ? 'success'
                                                            : scan.status === 'running'
                                                                ? 'info'
                                                                : scan.status === 'failed'
                                                                    ? 'critical'
                                                                    : 'default'
                                                    }
                                                >
                                                    {scan.status}
                                                </Badge>
                                            </td>
                                            <td className="py-4 px-6 text-text-primary font-semibold">
                                                {scan.vulnerabilities > 0 ? scan.vulnerabilities : '-'}
                                            </td>
                                            <td className="py-4 px-6">
                                                {scan.severity !== '-' ? (
                                                    <Badge
                                                        variant={
                                                            scan.severity === 'critical'
                                                                ? 'critical'
                                                                : scan.severity === 'high'
                                                                    ? 'high'
                                                                    : scan.severity === 'medium'
                                                                        ? 'medium'
                                                                        : 'low'
                                                        }
                                                    >
                                                        {scan.severity}
                                                    </Badge>
                                                ) : (
                                                    <span className="text-text-tertiary">-</span>
                                                )}
                                            </td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{scan.started}</td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{scan.duration}</td>
                                            <td className="py-4 px-6">
                                                <div className="flex items-center gap-2">
                                                    <button className="p-2 rounded-lg hover:bg-bg-hover text-text-secondary hover:text-accent-green transition-colors">
                                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                                        </svg>
                                                    </button>
                                                    {scan.status === 'running' && (
                                                        <button className="p-2 rounded-lg hover:bg-bg-hover text-text-secondary hover:text-status-high transition-colors">
                                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                                            </svg>
                                                        </button>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {/* Pagination */}
                        <div className="flex items-center justify-between px-6 py-4 border-t border-border-primary">
                            <div className="text-sm text-text-secondary">
                                Showing 1 to 8 of 1,247 scans
                            </div>
                            <div className="flex items-center gap-2">
                                <Button variant="outline" size="sm">Previous</Button>
                                <Button variant="primary" size="sm">1</Button>
                                <Button variant="ghost" size="sm">2</Button>
                                <Button variant="ghost" size="sm">3</Button>
                                <Button variant="ghost" size="sm">...</Button>
                                <Button variant="ghost" size="sm">156</Button>
                                <Button variant="outline" size="sm">Next</Button>
                            </div>
                        </div>
                    </Card>
                </Container>
            </div>
        </Layout>
    );
}
