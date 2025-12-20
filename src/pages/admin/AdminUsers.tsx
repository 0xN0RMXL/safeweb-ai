import { useState } from 'react';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Button from '@components/ui/Button';
import Input from '@components/ui/Input';
import Select from '@components/ui/Select';

export default function AdminUsers() {
    const [searchQuery, setSearchQuery] = useState('');
    const [filterPlan, setFilterPlan] = useState('all');
    const [filterStatus, setFilterStatus] = useState('all');

    const users = [
        { id: 1, name: 'John Doe', email: 'john@example.com', plan: 'Pro', status: 'active', scans: 156, joined: '2024-01-15', lastActive: '2 hours ago' },
        { id: 2, name: 'Jane Smith', email: 'jane@example.com', plan: 'Free', status: 'active', scans: 23, joined: '2024-02-20', lastActive: '1 day ago' },
        { id: 3, name: 'Mike Johnson', email: 'mike@example.com', plan: 'Enterprise', status: 'active', scans: 892, joined: '2023-11-08', lastActive: '30 min ago' },
        { id: 4, name: 'Sarah Wilson', email: 'sarah@example.com', plan: 'Pro', status: 'suspended', scans: 67, joined: '2024-03-12', lastActive: '5 days ago' },
        { id: 5, name: 'Tom Brown', email: 'tom@example.com', plan: 'Free', status: 'active', scans: 12, joined: '2024-03-18', lastActive: '3 hours ago' },
        { id: 6, name: 'Emily Davis', email: 'emily@example.com', plan: 'Pro', status: 'active', scans: 234, joined: '2023-12-05', lastActive: '1 hour ago' },
        { id: 7, name: 'David Lee', email: 'david@example.com', plan: 'Enterprise', status: 'active', scans: 1247, joined: '2023-09-22', lastActive: '15 min ago' },
        { id: 8, name: 'Lisa Anderson', email: 'lisa@example.com', plan: 'Free', status: 'inactive', scans: 5, joined: '2024-03-01', lastActive: '2 weeks ago' },
    ];

    const planOptions = [
        { value: 'all', label: 'All Plans' },
        { value: 'free', label: 'Free' },
        { value: 'pro', label: 'Pro' },
        { value: 'enterprise', label: 'Enterprise' },
    ];

    const statusOptions = [
        { value: 'all', label: 'All Status' },
        { value: 'active', label: 'Active' },
        { value: 'suspended', label: 'Suspended' },
        { value: 'inactive', label: 'Inactive' },
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-3xl font-heading font-bold text-text-primary mb-2">
                                User Management
                            </h1>
                            <p className="text-text-secondary">Manage all platform users</p>
                        </div>
                        <Button variant="primary">
                            Add New User
                        </Button>
                    </div>

                    {/* Stats Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                        <Card className="p-6">
                            <div className="text-sm text-text-tertiary mb-2">Total Users</div>
                            <div className="text-3xl font-bold text-text-primary">2,847</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-sm text-text-tertiary mb-2">Active Users</div>
                            <div className="text-3xl font-bold text-accent-green">2,453</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-sm text-text-tertiary mb-2">Pro Users</div>
                            <div className="text-3xl font-bold text-accent-blue">847</div>
                        </Card>
                        <Card className="p-6">
                            <div className="text-sm text-text-tertiary mb-2">Enterprise</div>
                            <div className="text-3xl font-bold text-text-primary">156</div>
                        </Card>
                    </div>

                    {/* Filters */}
                    <Card className="p-6 mb-6">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <Input
                                type="text"
                                placeholder="Search by name or email..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                leftIcon={
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                    </svg>
                                }
                            />
                            <Select
                                options={planOptions}
                                value={filterPlan}
                                onChange={(e) => setFilterPlan(e.target.value)}
                            />
                            <Select
                                options={statusOptions}
                                value={filterStatus}
                                onChange={(e) => setFilterStatus(e.target.value)}
                            />
                        </div>
                    </Card>

                    {/* Users Table */}
                    <Card className="overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full">
                                <thead>
                                    <tr className="bg-bg-secondary">
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">User</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Plan</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Status</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Scans</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Joined</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Last Active</th>
                                        <th className="text-left py-4 px-6 text-sm font-semibold text-text-secondary">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {users.map((user) => (
                                        <tr key={user.id} className="border-t border-border-primary hover:bg-bg-secondary/50">
                                            <td className="py-4 px-6">
                                                <div>
                                                    <div className="font-medium text-text-primary">{user.name}</div>
                                                    <div className="text-sm text-text-tertiary">{user.email}</div>
                                                </div>
                                            </td>
                                            <td className="py-4 px-6">
                                                <Badge variant={user.plan === 'Enterprise' ? 'info' : user.plan === 'Pro' ? 'success' : 'default'}>
                                                    {user.plan}
                                                </Badge>
                                            </td>
                                            <td className="py-4 px-6">
                                                <Badge variant={user.status === 'active' ? 'success' : user.status === 'suspended' ? 'high' : 'default'}>
                                                    {user.status}
                                                </Badge>
                                            </td>
                                            <td className="py-4 px-6 text-text-secondary">{user.scans}</td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{user.joined}</td>
                                            <td className="py-4 px-6 text-sm text-text-secondary">{user.lastActive}</td>
                                            <td className="py-4 px-6">
                                                <div className="flex items-center gap-2">
                                                    <button className="p-2 rounded-lg hover:bg-bg-hover text-text-secondary hover:text-accent-green transition-colors">
                                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                                                        </svg>
                                                    </button>
                                                    <button className="p-2 rounded-lg hover:bg-bg-hover text-text-secondary hover:text-status-high transition-colors">
                                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                                        </svg>
                                                    </button>
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
                                Showing 1 to 8 of 2,847 users
                            </div>
                            <div className="flex items-center gap-2">
                                <Button variant="outline" size="sm">Previous</Button>
                                <Button variant="ghost" size="sm">1</Button>
                                <Button variant="primary" size="sm">2</Button>
                                <Button variant="ghost" size="sm">3</Button>
                                <Button variant="ghost" size="sm">...</Button>
                                <Button variant="ghost" size="sm">356</Button>
                                <Button variant="outline" size="sm">Next</Button>
                            </div>
                        </div>
                    </Card>
                </Container>
            </div>
        </Layout>
    );
}
