import { Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Badge from '@components/ui/Badge';
import { formatDateTime } from '@utils/date';

export default function Dashboard() {
  // Mock data
  const stats = [
    {
      label: 'Total Scans',
      value: '24',
      change: '+12%',
      trend: 'up' as const,
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
        </svg>
      ),
    },
    {
      label: 'Critical Issues',
      value: '3',
      change: '-25%',
      trend: 'down' as const,
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
    },
    {
      label: 'Security Score',
      value: '87',
      change: '+5 pts',
      trend: 'up' as const,
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
    },
    {
      label: 'Last Scan',
      value: '2h ago',
      change: 'Completed',
      trend: 'neutral' as const,
      icon: (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
  ];

  const recentScans = [
    {
      id: '1',
      target: 'https://example.com',
      type: 'Website',
      status: 'completed' as const,
      date: new Date('2025-12-20T10:30:00'),
      vulnerabilities: { critical: 1, high: 2, medium: 5, low: 8 },
      score: 82,
    },
    {
      id: '2',
      target: 'https://api.example.com',
      type: 'API',
      status: 'completed' as const,
      date: new Date('2025-12-19T15:45:00'),
      vulnerabilities: { critical: 0, high: 1, medium: 3, low: 4 },
      score: 91,
    },
    {
      id: '3',
      target: 'upload.pdf',
      type: 'File',
      status: 'scanning' as const,
      date: new Date('2025-12-20T12:15:00'),
      vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
      score: 0,
    },
  ];

  const vulnerabilityOverview = [
    { severity: 'critical' as const, count: 3, label: 'Critical' },
    { severity: 'high' as const, count: 7, label: 'High' },
    { severity: 'medium' as const, count: 15, label: 'Medium' },
    { severity: 'low' as const, count: 28, label: 'Low' },
  ];

  return (
    <Layout>
      <div className="py-12">
        <Container>
          {/* Header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8">
            <div>
              <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                Security Dashboard
              </h1>
              <p className="text-text-secondary">
                Monitor your security posture and recent scan activity
              </p>
            </div>
            <Link to="/scan">
              <Button variant="primary" className="mt-4 md:mt-0">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
                New Scan
              </Button>
            </Link>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {stats.map((stat, index) => (
              <Card key={index} className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="w-12 h-12 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green">
                    {stat.icon}
                  </div>
                  <span
                    className={`text-sm font-medium ${
                      stat.trend === 'up'
                        ? 'text-status-low'
                        : stat.trend === 'down'
                        ? 'text-status-critical'
                        : 'text-text-tertiary'
                    }`}
                  >
                    {stat.change}
                  </span>
                </div>
                <div className="text-3xl font-bold text-text-primary mb-1">
                  {stat.value}
                </div>
                <div className="text-sm text-text-tertiary">{stat.label}</div>
              </Card>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Recent Scans */}
            <Card className="lg:col-span-2 p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-heading font-semibold text-text-primary">
                  Recent Scans
                </h2>
                <Link
                  to="/history"
                  className="text-sm text-accent-green hover:text-accent-green-hover transition-colors"
                >
                  View All
                </Link>
              </div>

              <div className="space-y-4">
                {recentScans.map((scan) => (
                  <div
                    key={scan.id}
                    className="p-4 rounded-lg bg-bg-secondary border border-border-primary hover:bg-bg-hover transition-colors duration-200"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="font-medium text-text-primary font-mono text-sm">
                            {scan.target}
                          </h3>
                          <Badge variant="default" size="sm">
                            {scan.type}
                          </Badge>
                          {scan.status === 'scanning' ? (
                            <Badge variant="info" size="sm">
                              Scanning...
                            </Badge>
                          ) : (
                            <Badge variant="low" size="sm">
                              Completed
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-text-tertiary">
                          {formatDateTime(scan.date)}
                        </p>
                      </div>
                      {scan.status === 'completed' && (
                        <div className="text-right">
                          <div className="text-2xl font-bold text-accent-green">
                            {scan.score}
                          </div>
                          <div className="text-xs text-text-tertiary">Score</div>
                        </div>
                      )}
                    </div>

                    {scan.status === 'completed' && (
                      <div className="flex items-center gap-4 text-xs">
                        {scan.vulnerabilities.critical > 0 && (
                          <span className="text-status-critical">
                            {scan.vulnerabilities.critical} Critical
                          </span>
                        )}
                        {scan.vulnerabilities.high > 0 && (
                          <span className="text-status-high">
                            {scan.vulnerabilities.high} High
                          </span>
                        )}
                        {scan.vulnerabilities.medium > 0 && (
                          <span className="text-status-medium">
                            {scan.vulnerabilities.medium} Medium
                          </span>
                        )}
                        {scan.vulnerabilities.low > 0 && (
                          <span className="text-status-low">
                            {scan.vulnerabilities.low} Low
                          </span>
                        )}
                      </div>
                    )}

                    {scan.status === 'scanning' && (
                      <div className="mt-2">
                        <div className="h-1.5 bg-bg-tertiary rounded-full overflow-hidden">
                          <div className="h-full w-2/3 bg-accent-green animate-pulse"></div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Card>

            {/* Vulnerability Overview */}
            <Card className="p-6">
              <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                Vulnerabilities
              </h2>

              <div className="space-y-4">
                {vulnerabilityOverview.map((item) => (
                  <div key={item.severity}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Badge variant={item.severity} size="sm">
                          {item.label}
                        </Badge>
                      </div>
                      <span className="text-2xl font-bold text-text-primary">
                        {item.count}
                      </span>
                    </div>
                    <div className="h-2 bg-bg-tertiary rounded-full overflow-hidden">
                      <div
                        className={`h-full ${
                          item.severity === 'critical'
                            ? 'bg-status-critical'
                            : item.severity === 'high'
                            ? 'bg-status-high'
                            : item.severity === 'medium'
                            ? 'bg-status-medium'
                            : 'bg-status-low'
                        }`}
                        style={{ width: `${(item.count / 60) * 100}%` }}
                      ></div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-6 pt-6 border-t border-border-primary">
                <Link to="/history">
                  <Button variant="outline" size="sm" className="w-full">
                    View Detailed Report
                  </Button>
                </Link>
              </div>
            </Card>
          </div>

          {/* Quick Actions */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8">
            <Card className="p-6 hover:shadow-card-hover transition-all duration-300 group cursor-pointer">
              <Link to="/scan">
                <div className="w-14 h-14 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-4 group-hover:bg-accent-green/20 transition-colors">
                  <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                </div>
                <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                  Scan Website
                </h3>
                <p className="text-sm text-text-tertiary">
                  Perform comprehensive security analysis on any website or web application
                </p>
              </Link>
            </Card>

            <Card className="p-6 hover:shadow-card-hover transition-all duration-300 group cursor-pointer">
              <Link to="/learn">
                <div className="w-14 h-14 rounded-lg bg-accent-blue/10 flex items-center justify-center text-accent-blue mb-4 group-hover:bg-accent-blue/20 transition-colors">
                  <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                  </svg>
                </div>
                <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                  Learn Security
                </h3>
                <p className="text-sm text-text-tertiary">
                  Access tutorials and best practices to strengthen your security knowledge
                </p>
              </Link>
            </Card>

            <Card className="p-6 hover:shadow-card-hover transition-all duration-300 group cursor-pointer">
              <Link to="/docs">
                <div className="w-14 h-14 rounded-lg bg-accent-green/10 flex items-center justify-center text-accent-green mb-4 group-hover:bg-accent-green/20 transition-colors">
                  <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                  Documentation
                </h3>
                <p className="text-sm text-text-tertiary">
                  Explore API documentation and integration guides for developers
                </p>
              </Link>
            </Card>
          </div>
        </Container>
      </div>
    </Layout>
  );
}
