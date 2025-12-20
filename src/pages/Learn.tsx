import { Link } from 'react-router-dom';
import Layout from '@components/layout/Layout';
import Container from '@components/ui/Container';
import Card from '@components/ui/Card';
import Badge from '@components/ui/Badge';
import Input from '@components/ui/Input';
import { formatDate } from '@utils/date';

export default function Learn() {
    const articles = [
        {
            id: '1',
            title: 'Understanding SQL Injection: Detection and Prevention',
            excerpt: 'Learn how SQL injection attacks work, how to detect them, and implement secure coding practices to prevent them in your applications.',
            category: 'Injection Attacks',
            author: 'Security Team',
            date: new Date('2025-12-18'),
            readTime: 8,
            image: null,
        },
        {
            id: '2',
            title: 'Cross-Site Scripting (XSS) Attack Patterns',
            excerpt: 'Comprehensive guide to XSS vulnerabilities including reflected, stored, and DOM-based XSS with real-world examples.',
            category: 'XSS',
            author: 'Security Team',
            date: new Date('2025-12-15'),
            readTime: 10,
            image: null,
        },
        {
            id: '3',
            title: 'OWASP Top 10 2025: Complete Guide',
            excerpt: 'Deep dive into the latest OWASP Top 10 vulnerabilities with practical examples and mitigation strategies.',
            category: 'Best Practices',
            author: 'Security Team',
            date: new Date('2025-12-12'),
            readTime: 15,
            image: null,
        },
        {
            id: '4',
            title: 'Securing REST APIs: A Comprehensive Checklist',
            excerpt: 'Essential security measures for API development including authentication, rate limiting, and input validation.',
            category: 'API Security',
            author: 'Security Team',
            date: new Date('2025-12-10'),
            readTime: 12,
            image: null,
        },
        {
            id: '5',
            title: 'Implementing Content Security Policy (CSP)',
            excerpt: 'Step-by-step guide to implementing CSP headers to prevent XSS attacks and data injection.',
            category: 'Security Headers',
            author: 'Security Team',
            date: new Date('2025-12-08'),
            readTime: 9,
            image: null,
        },
        {
            id: '6',
            title: 'Authentication Best Practices in 2025',
            excerpt: 'Modern authentication strategies including MFA, OAuth 2.0, and passwordless authentication.',
            category: 'Authentication',
            author: 'Security Team',
            date: new Date('2025-12-05'),
            readTime: 11,
            image: null,
        },
    ];

    const categories = [
        'All Articles',
        'Injection Attacks',
        'XSS',
        'Best Practices',
        'API Security',
        'Authentication',
        'Security Headers',
    ];

    return (
        <Layout>
            <div className="py-12">
                <Container>
                    {/* Header */}
                    <div className="text-center mb-12">
                        <h1 className="text-4xl font-heading font-bold text-text-primary mb-4">
                            Security Learning Center
                        </h1>
                        <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                            Expand your security knowledge with in-depth articles, tutorials, and best practices
                        </p>
                    </div>

                    {/* Search */}
                    <div className="max-w-2xl mx-auto mb-12">
                        <Input
                            type="text"
                            placeholder="Search articles..."
                            leftIcon={
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                </svg>
                            }
                        />
                    </div>

                    {/* Categories */}
                    <div className="flex flex-wrap items-center justify-center gap-3 mb-12">
                        {categories.map((category) => (
                            <button
                                key={category}
                                className="px-4 py-2 rounded-lg bg-bg-card border border-border-primary text-sm text-text-secondary hover:text-accent-green hover:border-accent-green transition-all duration-200"
                            >
                                {category}
                            </button>
                        ))}
                    </div>

                    {/* Featured Article */}
                    <Card className="p-8 mb-12 hover:shadow-card-hover transition-all duration-300">
                        <div className="flex items-start gap-3 mb-3">
                            <Badge variant="info" size="sm">Featured</Badge>
                            <Badge variant="default" size="sm">{articles[0].category}</Badge>
                        </div>
                        <Link to={`/learn/${articles[0].id}`}>
                            <h2 className="text-3xl font-heading font-bold text-text-primary mb-4 hover:text-accent-green transition-colors">
                                {articles[0].title}
                            </h2>
                        </Link>
                        <p className="text-lg text-text-secondary mb-6 leading-relaxed">
                            {articles[0].excerpt}
                        </p>
                        <div className="flex items-center gap-4 text-sm text-text-tertiary">
                            <span>{articles[0].author}</span>
                            <span>•</span>
                            <span>{formatDate(articles[0].date)}</span>
                            <span>•</span>
                            <span>{articles[0].readTime} min read</span>
                        </div>
                    </Card>

                    {/* Articles Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {articles.slice(1).map((article) => (
                            <Card key={article.id} hover className="p-6 flex flex-col">
                                <div className="mb-3">
                                    <Badge variant="default" size="sm">{article.category}</Badge>
                                </div>
                                <Link to={`/learn/${article.id}`}>
                                    <h3 className="text-xl font-heading font-semibold text-text-primary mb-3 hover:text-accent-green transition-colors">
                                        {article.title}
                                    </h3>
                                </Link>
                                <p className="text-sm text-text-secondary mb-4 leading-relaxed flex-1">
                                    {article.excerpt}
                                </p>
                                <div className="flex items-center justify-between text-xs text-text-tertiary pt-4 border-t border-border-primary">
                                    <span>{formatDate(article.date)}</span>
                                    <span>{article.readTime} min read</span>
                                </div>
                            </Card>
                        ))}
                    </div>

                    {/* CTA */}
                    <Card className="mt-12 p-8 bg-gradient-to-br from-accent-green/5 to-accent-blue/5 border-accent-green/20 text-center">
                        <h3 className="text-2xl font-heading font-bold text-text-primary mb-3">
                            Want to Contribute?
                        </h3>
                        <p className="text-text-secondary mb-6 max-w-2xl mx-auto">
                            Share your security knowledge with the community. We're always looking for quality content.
                        </p>
                        <Link to="/contact">
                            <button className="px-6 py-3 rounded-lg bg-accent-green text-bg-primary font-medium hover:bg-accent-green-hover transition-colors">
                                Submit an Article
                            </button>
                        </Link>
                    </Card>
                </Container>
            </div>
        </Layout>
    );
}
