import { useState } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Input from '@components/ui/Input';
import Button from '@components/ui/Button';
import Badge from '@components/ui/Badge';

export default function Profile() {
    const [isEditing, setIsEditing] = useState(false);
    const [userData, setUserData] = useState({
        name: 'Security Admin',
        email: 'admin@safeweb.ai',
        company: 'SafeWeb AI',
        role: 'Security Engineer',
    });

    const handleSave = () => {
        setIsEditing(false);
        alert('Profile updated successfully!');
    };

    const apiKeys = [
        {
            id: 'sk_live_abc123xyz',
            name: 'Production API',
            created: '2024-01-15',
            lastUsed: '2 hours ago',
            scans: 1243,
        },
        {
            id: 'sk_test_def456uvw',
            name: 'Development API',
            created: '2024-02-01',
            lastUsed: '1 day ago',
            scans: 89,
        },
    ];

    const subscription = {
        plan: 'Pro',
        status: 'active',
        scansUsed: 847,
        scansLimit: 'Unlimited',
        billingCycle: 'Monthly',
        nextBilling: '2024-03-15',
        amount: '$49.00',
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    <div className="mb-8">
                        <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                            Account Settings
                        </h1>
                        <p className="text-text-secondary">Manage your profile, subscription, and API keys</p>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Main Content */}
                        <div className="lg:col-span-2 space-y-8">
                            {/* Profile Information */}
                            <Card className="p-6">
                                <div className="flex items-center justify-between mb-6">
                                    <h2 className="text-xl font-heading font-semibold text-text-primary">
                                        Profile Information
                                    </h2>
                                    {!isEditing ? (
                                        <Button variant="outline" size="sm" onClick={() => setIsEditing(true)}>
                                            Edit Profile
                                        </Button>
                                    ) : (
                                        <div className="flex items-center gap-2">
                                            <Button variant="outline" size="sm" onClick={() => setIsEditing(false)}>
                                                Cancel
                                            </Button>
                                            <Button variant="primary" size="sm" onClick={handleSave}>
                                                Save Changes
                                            </Button>
                                        </div>
                                    )}
                                </div>

                                <div className="space-y-4">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <Input
                                            type="text"
                                            label="Full Name"
                                            value={userData.name}
                                            onChange={(e) => setUserData({ ...userData, name: e.target.value })}
                                            disabled={!isEditing}
                                        />
                                        <Input
                                            type="email"
                                            label="Email Address"
                                            value={userData.email}
                                            onChange={(e) => setUserData({ ...userData, email: e.target.value })}
                                            disabled={!isEditing}
                                        />
                                    </div>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <Input
                                            type="text"
                                            label="Company"
                                            value={userData.company}
                                            onChange={(e) => setUserData({ ...userData, company: e.target.value })}
                                            disabled={!isEditing}
                                        />
                                        <Input
                                            type="text"
                                            label="Role"
                                            value={userData.role}
                                            onChange={(e) => setUserData({ ...userData, role: e.target.value })}
                                            disabled={!isEditing}
                                        />
                                    </div>
                                </div>
                            </Card>

                            {/* API Keys */}
                            <Card className="p-6">
                                <div className="flex items-center justify-between mb-6">
                                    <div>
                                        <h2 className="text-xl font-heading font-semibold text-text-primary mb-1">
                                            API Keys
                                        </h2>
                                        <p className="text-sm text-text-tertiary">
                                            Manage your API keys for integration
                                        </p>
                                    </div>
                                    <Button variant="primary" size="sm">
                                        Generate New Key
                                    </Button>
                                </div>

                                <div className="space-y-4">
                                    {apiKeys.map((key) => (
                                        <div
                                            key={key.id}
                                            className="p-4 rounded-lg bg-bg-secondary border border-border-primary"
                                        >
                                            <div className="flex items-start justify-between mb-3">
                                                <div>
                                                    <div className="font-medium text-text-primary mb-1">{key.name}</div>
                                                    <div className="text-sm text-text-tertiary font-mono">{key.id}</div>
                                                </div>
                                                <Button variant="ghost" size="sm">
                                                    Revoke
                                                </Button>
                                            </div>
                                            <div className="grid grid-cols-3 gap-4 text-sm">
                                                <div>
                                                    <div className="text-text-tertiary mb-1">Created</div>
                                                    <div className="text-text-secondary">{key.created}</div>
                                                </div>
                                                <div>
                                                    <div className="text-text-tertiary mb-1">Last Used</div>
                                                    <div className="text-text-secondary">{key.lastUsed}</div>
                                                </div>
                                                <div>
                                                    <div className="text-text-tertiary mb-1">Total Scans</div>
                                                    <div className="text-text-secondary">{key.scans.toLocaleString()}</div>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                <div className="mt-4 p-4 rounded-lg bg-accent-blue/10 border border-accent-blue/20">
                                    <div className="flex items-start gap-3">
                                        <svg
                                            className="w-5 h-5 text-accent-blue flex-shrink-0 mt-0.5"
                                            fill="none"
                                            stroke="currentColor"
                                            viewBox="0 0 24 24"
                                        >
                                            <path
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                                strokeWidth={2}
                                                d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                                            />
                                        </svg>
                                        <div className="text-sm">
                                            <div className="text-text-primary font-medium mb-1">Keep your keys secure</div>
                                            <div className="text-text-tertiary">
                                                Never share your API keys publicly or commit them to version control.
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </Card>

                            {/* Security */}
                            <Card className="p-6">
                                <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                    Security Settings
                                </h2>
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">Password</div>
                                            <div className="text-sm text-text-tertiary">Last changed 3 months ago</div>
                                        </div>
                                        <Button variant="outline" size="sm">
                                            Change Password
                                        </Button>
                                    </div>
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">
                                                Two-Factor Authentication
                                            </div>
                                            <div className="text-sm text-text-tertiary">Add an extra layer of security</div>
                                        </div>
                                        <Button variant="outline" size="sm">
                                            Enable 2FA
                                        </Button>
                                    </div>
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">Active Sessions</div>
                                            <div className="text-sm text-text-tertiary">Manage your active sessions</div>
                                        </div>
                                        <Button variant="outline" size="sm">
                                            View Sessions
                                        </Button>
                                    </div>
                                </div>
                            </Card>
                        </div>

                        {/* Sidebar */}
                        <div className="space-y-6">
                            {/* Subscription */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    Subscription
                                </h3>
                                <div className="space-y-4">
                                    <div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Current Plan</span>
                                            <Badge variant="success">{subscription.plan}</Badge>
                                        </div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Status</span>
                                            <span className="text-sm text-accent-green capitalize">
                                                {subscription.status}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Billing Cycle</span>
                                            <span className="text-sm text-text-secondary">{subscription.billingCycle}</span>
                                        </div>
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm text-text-tertiary">Amount</span>
                                            <span className="text-sm font-semibold text-text-primary">
                                                {subscription.amount}
                                            </span>
                                        </div>
                                    </div>

                                    <div className="pt-4 border-t border-border-primary">
                                        <div className="text-sm text-text-tertiary mb-2">Scans This Month</div>
                                        <div className="text-2xl font-bold text-accent-green mb-1">
                                            {subscription.scansUsed.toLocaleString()}
                                        </div>
                                        <div className="text-sm text-text-tertiary">{subscription.scansLimit} available</div>
                                    </div>

                                    <div className="space-y-2 pt-4 border-t border-border-primary">
                                        <Button variant="outline" size="sm" className="w-full">
                                            Upgrade Plan
                                        </Button>
                                        <Button variant="ghost" size="sm" className="w-full">
                                            Cancel Subscription
                                        </Button>
                                    </div>
                                </div>
                            </Card>

                            {/* Usage Stats */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    Usage Statistics
                                </h3>
                                <div className="space-y-4">
                                    <div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Total Scans</span>
                                            <span className="text-sm font-semibold text-text-primary">1,932</span>
                                        </div>
                                        <div className="flex items-center justify-between mb-2">
                                            <span className="text-sm text-text-tertiary">Vulnerabilities Found</span>
                                            <span className="text-sm font-semibold text-text-primary">4,521</span>
                                        </div>
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm text-text-tertiary">Issues Fixed</span>
                                            <span className="text-sm font-semibold text-accent-green">3,847</span>
                                        </div>
                                    </div>
                                </div>
                            </Card>

                            {/* Support */}
                            <Card className="p-6 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-2">
                                    Need Help?
                                </h3>
                                <p className="text-sm text-text-secondary mb-4">
                                    Contact our support team for assistance
                                </p>
                                <Button variant="outline" size="sm" className="w-full">
                                    Contact Support
                                </Button>
                            </Card>
                        </div>
                    </div>
                </Container>
            </div>
        </Layout>
    );
}
