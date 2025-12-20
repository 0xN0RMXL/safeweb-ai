import { useState } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Badge from '@components/ui/Badge';

export default function AdminML() {
    const [selectedModel, setSelectedModel] = useState('vulnerability-detector-v3');

    const models = [
        {
            id: 'vulnerability-detector-v3',
            name: 'Vulnerability Detector v3.2',
            status: 'active',
            accuracy: 94.7,
            lastTrained: '2024-03-15',
            trainingData: '2.4M samples',
            version: '3.2.1',
        },
        {
            id: 'xss-detector',
            name: 'XSS Detector v2.1',
            status: 'active',
            accuracy: 96.3,
            lastTrained: '2024-03-10',
            trainingData: '850K samples',
            version: '2.1.0',
        },
        {
            id: 'sql-injection',
            name: 'SQL Injection Detector',
            status: 'training',
            accuracy: 95.1,
            lastTrained: '2024-03-18',
            trainingData: '1.2M samples',
            version: '4.0.0-beta',
        },
    ];

    const trainingJobs = [
        { id: 1, model: 'Vulnerability Detector v3.3', status: 'running', progress: 67, startTime: '2 hours ago', eta: '1 hour' },
        { id: 2, model: 'CSRF Detector v1.5', status: 'queued', progress: 0, startTime: '-', eta: '3 hours' },
        { id: 3, model: 'Auth Bypass Detector', status: 'completed', progress: 100, startTime: '5 hours ago', eta: '-' },
        { id: 4, model: 'File Upload Validator', status: 'failed', progress: 45, startTime: '1 day ago', eta: '-' },
    ];

    const datasets = [
        { id: 1, name: 'OWASP Test Suite 2024', samples: 450000, size: '2.3 GB', updated: '2024-03-15' },
        { id: 2, name: 'Real-World Vulnerabilities', samples: 1200000, size: '5.7 GB', updated: '2024-03-12' },
        { id: 3, name: 'Synthetic Attack Patterns', samples: 800000, size: '3.2 GB', updated: '2024-03-08' },
        { id: 4, name: 'CVE Database Mirror', samples: 350000, size: '1.8 GB', updated: '2024-03-18' },
    ];

    const metrics = [
        { label: 'Total Models', value: '12', change: '+2' },
        { label: 'Active Models', value: '8', change: '0' },
        { label: 'Avg Accuracy', value: '95.2%', change: '+1.3%' },
        { label: 'Training Jobs', value: '3', change: '+1' },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                ML Model Management
                            </h1>
                            <p className="text-text-secondary">Train and manage AI detection models</p>
                        </div>
                        <Button variant="primary">
                            Train New Model
                        </Button>
                    </div>

                    {/* Metrics */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                        {metrics.map((metric, index) => (
                            <Card key={index} className="p-6">
                                <div className="text-sm text-text-tertiary mb-2">{metric.label}</div>
                                <div className="flex items-end justify-between">
                                    <div className="text-3xl font-bold text-text-primary">{metric.value}</div>
                                    <span className="text-sm text-accent-green">{metric.change}</span>
                                </div>
                            </Card>
                        ))}
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
                        {/* Active Models */}
                        <Card className="lg:col-span-2 p-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                Active Models
                            </h2>
                            <div className="space-y-4">
                                {models.map((model) => (
                                    <div
                                        key={model.id}
                                        className={`p-4 rounded-lg border transition-all cursor-pointer ${selectedModel === model.id
                                                ? 'border-accent-green bg-accent-green/5'
                                                : 'border-border-primary hover:border-accent-green/50'
                                            }`}
                                        onClick={() => setSelectedModel(model.id)}
                                    >
                                        <div className="flex items-start justify-between mb-3">
                                            <div>
                                                <div className="font-semibold text-text-primary mb-1">{model.name}</div>
                                                <div className="text-sm text-text-tertiary">Version {model.version}</div>
                                            </div>
                                            <Badge variant={model.status === 'active' ? 'success' : 'info'}>
                                                {model.status}
                                            </Badge>
                                        </div>
                                        <div className="grid grid-cols-3 gap-4 text-sm">
                                            <div>
                                                <div className="text-text-tertiary mb-1">Accuracy</div>
                                                <div className="font-semibold text-accent-green">{model.accuracy}%</div>
                                            </div>
                                            <div>
                                                <div className="text-text-tertiary mb-1">Training Data</div>
                                                <div className="font-semibold text-text-primary">{model.trainingData}</div>
                                            </div>
                                            <div>
                                                <div className="text-text-tertiary mb-1">Last Trained</div>
                                                <div className="font-semibold text-text-primary">{model.lastTrained}</div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </Card>

                        {/* Model Actions */}
                        <Card className="p-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                Model Actions
                            </h2>
                            <div className="space-y-3">
                                <Button variant="primary" className="w-full">
                                    Retrain Model
                                </Button>
                                <Button variant="outline" className="w-full">
                                    Deploy to Production
                                </Button>
                                <Button variant="outline" className="w-full">
                                    Export Model
                                </Button>
                                <Button variant="outline" className="w-full">
                                    View Metrics
                                </Button>
                                <Button variant="outline" className="w-full">
                                    Compare Models
                                </Button>
                                <Button variant="ghost" className="w-full text-status-high">
                                    Archive Model
                                </Button>
                            </div>
                        </Card>
                    </div>

                    {/* Training Jobs */}
                    <Card className="p-6 mb-8">
                        <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                            Training Jobs
                        </h2>
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="border-b border-border-primary">
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Model</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Status</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Progress</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Started</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">ETA</th>
                                        <th className="text-left py-3 px-4 text-sm font-semibold text-text-secondary">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {trainingJobs.map((job) => (
                                        <tr key={job.id} className="border-b border-border-primary/50 hover:bg-bg-secondary/50">
                                            <td className="py-3 px-4 font-medium text-text-primary">{job.model}</td>
                                            <td className="py-3 px-4">
                                                <Badge
                                                    variant={
                                                        job.status === 'completed'
                                                            ? 'success'
                                                            : job.status === 'running'
                                                                ? 'info'
                                                                : job.status === 'failed'
                                                                    ? 'critical'
                                                                    : 'default'
                                                    }
                                                >
                                                    {job.status}
                                                </Badge>
                                            </td>
                                            <td className="py-3 px-4">
                                                <div className="flex items-center gap-3">
                                                    <div className="flex-1 h-2 bg-bg-secondary rounded-full overflow-hidden">
                                                        <div
                                                            className="h-full bg-accent-green rounded-full transition-all"
                                                            style={{ width: `${job.progress}%` }}
                                                        />
                                                    </div>
                                                    <span className="text-sm text-text-secondary">{job.progress}%</span>
                                                </div>
                                            </td>
                                            <td className="py-3 px-4 text-sm text-text-secondary">{job.startTime}</td>
                                            <td className="py-3 px-4 text-sm text-text-secondary">{job.eta}</td>
                                            <td className="py-3 px-4">
                                                <Button variant="ghost" size="sm">
                                                    {job.status === 'running' ? 'Cancel' : 'View'}
                                                </Button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </Card>

                    {/* Datasets */}
                    <Card className="p-6">
                        <div className="flex items-center justify-between mb-6">
                            <h2 className="text-xl font-heading font-semibold text-text-primary">
                                Training Datasets
                            </h2>
                            <Button variant="outline" size="sm">
                                Upload Dataset
                            </Button>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {datasets.map((dataset) => (
                                <div
                                    key={dataset.id}
                                    className="p-4 rounded-lg bg-bg-secondary border border-border-primary hover:border-accent-green/50 transition-all"
                                >
                                    <div className="font-semibold text-text-primary mb-3">{dataset.name}</div>
                                    <div className="grid grid-cols-3 gap-3 text-sm">
                                        <div>
                                            <div className="text-text-tertiary mb-1">Samples</div>
                                            <div className="font-semibold text-text-primary">
                                                {(dataset.samples / 1000).toFixed(0)}K
                                            </div>
                                        </div>
                                        <div>
                                            <div className="text-text-tertiary mb-1">Size</div>
                                            <div className="font-semibold text-text-primary">{dataset.size}</div>
                                        </div>
                                        <div>
                                            <div className="text-text-tertiary mb-1">Updated</div>
                                            <div className="font-semibold text-text-primary">{dataset.updated}</div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </Card>
                </Container>
            </div>
        </Layout>
    );
}
