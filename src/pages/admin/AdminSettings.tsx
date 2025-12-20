import { useState } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';

export default function AdminSettings() {
    const [settings, setSettings] = useState({
        siteName: 'SafeWeb AI',
        siteUrl: 'https://safeweb-ai.com',
        adminEmail: 'admin@safeweb.ai',
        supportEmail: 'support@safeweb.ai',
        maxScansPerUser: '100',
        scanTimeout: '300',
        apiRateLimit: '1000',
        maintenanceMode: false,
        registrationEnabled: true,
        emailNotifications: true,
    });

    const handleSave = () => {
        alert('Settings saved successfully!');
    };

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                System Settings
                            </h1>
                            <p className="text-text-secondary">Configure platform settings and preferences</p>
                        </div>
                        <Button variant="primary" onClick={handleSave}>
                            Save Changes
                        </Button>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        {/* Main Settings */}
                        <div className="lg:col-span-2 space-y-6">
                            {/* General Settings */}
                            <Card className="p-6">
                                <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                    General Settings
                                </h2>
                                <div className="space-y-4">
                                    <Input
                                        type="text"
                                        label="Site Name"
                                        value={settings.siteName}
                                        onChange={(e) => setSettings({ ...settings, siteName: e.target.value })}
                                    />
                                    <Input
                                        type="url"
                                        label="Site URL"
                                        value={settings.siteUrl}
                                        onChange={(e) => setSettings({ ...settings, siteUrl: e.target.value })}
                                    />
                                    <Input
                                        type="email"
                                        label="Admin Email"
                                        value={settings.adminEmail}
                                        onChange={(e) => setSettings({ ...settings, adminEmail: e.target.value })}
                                    />
                                    <Input
                                        type="email"
                                        label="Support Email"
                                        value={settings.supportEmail}
                                        onChange={(e) => setSettings({ ...settings, supportEmail: e.target.value })}
                                    />
                                </div>
                            </Card>

                            {/* Scan Settings */}
                            <Card className="p-6">
                                <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                    Scan Configuration
                                </h2>
                                <div className="space-y-4">
                                    <Input
                                        type="number"
                                        label="Max Scans Per User (per month)"
                                        value={settings.maxScansPerUser}
                                        onChange={(e) => setSettings({ ...settings, maxScansPerUser: e.target.value })}
                                        helperText="Set to 0 for unlimited"
                                    />
                                    <Input
                                        type="number"
                                        label="Scan Timeout (seconds)"
                                        value={settings.scanTimeout}
                                        onChange={(e) => setSettings({ ...settings, scanTimeout: e.target.value })}
                                        helperText="Maximum duration for a single scan"
                                    />
                                    <Input
                                        type="number"
                                        label="API Rate Limit (requests/hour)"
                                        value={settings.apiRateLimit}
                                        onChange={(e) => setSettings({ ...settings, apiRateLimit: e.target.value })}
                                    />
                                </div>
                            </Card>

                            {/* Security Settings */}
                            <Card className="p-6">
                                <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                    Security Settings
                                </h2>
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">Two-Factor Authentication</div>
                                            <div className="text-sm text-text-tertiary">Require 2FA for all admin accounts</div>
                                        </div>
                                        <label className="relative inline-flex items-center cursor-pointer">
                                            <input type="checkbox" className="sr-only peer" defaultChecked />
                                            <div className="w-11 h-6 bg-bg-tertiary rounded-full peer peer-checked:bg-accent-green peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all"></div>
                                        </label>
                                    </div>
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">Password Expiry</div>
                                            <div className="text-sm text-text-tertiary">Force password change every 90 days</div>
                                        </div>
                                        <label className="relative inline-flex items-center cursor-pointer">
                                            <input type="checkbox" className="sr-only peer" />
                                            <div className="w-11 h-6 bg-bg-tertiary rounded-full peer peer-checked:bg-accent-green peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all"></div>
                                        </label>
                                    </div>
                                    <div className="flex items-center justify-between p-4 rounded-lg bg-bg-secondary border border-border-primary">
                                        <div>
                                            <div className="font-medium text-text-primary mb-1">IP Whitelist</div>
                                            <div className="text-sm text-text-tertiary">Restrict admin access by IP address</div>
                                        </div>
                                        <label className="relative inline-flex items-center cursor-pointer">
                                            <input type="checkbox" className="sr-only peer" />
                                            <div className="w-11 h-6 bg-bg-tertiary rounded-full peer peer-checked:bg-accent-green peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all"></div>
                                        </label>
                                    </div>
                                </div>
                            </Card>

                            {/* Email Settings */}
                            <Card className="p-6">
                                <h2 className="text-xl font-heading font-semibold text-text-primary mb-6">
                                    Email Configuration
                                </h2>
                                <div className="space-y-4">
                                    <Input type="text" label="SMTP Host" placeholder="smtp.example.com" />
                                    <Input type="number" label="SMTP Port" placeholder="587" />
                                    <Input type="text" label="SMTP Username" placeholder="noreply@safeweb.ai" />
                                    <Input type="password" label="SMTP Password" placeholder="••••••••" />
                                    <Button variant="outline" size="sm">
                                        Test Email Configuration
                                    </Button>
                                </div>
                            </Card>
                        </div>

                        {/* Sidebar */}
                        <div className="space-y-6">
                            {/* System Status */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    System Status
                                </h3>
                                <div className="space-y-3">
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-text-tertiary">Maintenance Mode</span>
                                        <label className="relative inline-flex items-center cursor-pointer">
                                            <input
                                                type="checkbox"
                                                className="sr-only peer"
                                                checked={settings.maintenanceMode}
                                                onChange={(e) => setSettings({ ...settings, maintenanceMode: e.target.checked })}
                                            />
                                            <div className="w-11 h-6 bg-bg-tertiary rounded-full peer peer-checked:bg-accent-green peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all"></div>
                                        </label>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-text-tertiary">Registration Enabled</span>
                                        <label className="relative inline-flex items-center cursor-pointer">
                                            <input
                                                type="checkbox"
                                                className="sr-only peer"
                                                checked={settings.registrationEnabled}
                                                onChange={(e) => setSettings({ ...settings, registrationEnabled: e.target.checked })}
                                            />
                                            <div className="w-11 h-6 bg-bg-tertiary rounded-full peer peer-checked:bg-accent-green peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all"></div>
                                        </label>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-text-tertiary">Email Notifications</span>
                                        <label className="relative inline-flex items-center cursor-pointer">
                                            <input
                                                type="checkbox"
                                                className="sr-only peer"
                                                checked={settings.emailNotifications}
                                                onChange={(e) => setSettings({ ...settings, emailNotifications: e.target.checked })}
                                            />
                                            <div className="w-11 h-6 bg-bg-tertiary rounded-full peer peer-checked:bg-accent-green peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all"></div>
                                        </label>
                                    </div>
                                </div>
                            </Card>

                            {/* Quick Actions */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    Quick Actions
                                </h3>
                                <div className="space-y-2">
                                    <Button variant="outline" size="sm" className="w-full">
                                        Clear Cache
                                    </Button>
                                    <Button variant="outline" size="sm" className="w-full">
                                        Backup Database
                                    </Button>
                                    <Button variant="outline" size="sm" className="w-full">
                                        View Logs
                                    </Button>
                                    <Button variant="ghost" size="sm" className="w-full text-status-high">
                                        Reset Settings
                                    </Button>
                                </div>
                            </Card>

                            {/* System Info */}
                            <Card className="p-6">
                                <h3 className="text-lg font-heading font-semibold text-text-primary mb-4">
                                    System Information
                                </h3>
                                <div className="space-y-3 text-sm">
                                    <div className="flex justify-between">
                                        <span className="text-text-tertiary">Version</span>
                                        <span className="text-text-primary font-medium">1.0.0</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-text-tertiary">Database</span>
                                        <span className="text-text-primary font-medium">PostgreSQL</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-text-tertiary">Storage Used</span>
                                        <span className="text-text-primary font-medium">45.2 GB</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-text-tertiary">Last Backup</span>
                                        <span className="text-text-primary font-medium">2 hours ago</span>
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
