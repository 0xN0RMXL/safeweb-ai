import { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import Button from '@components/ui/Button';
import Container from '@components/ui/Container';

export default function Navbar() {
    const [isScrolled, setIsScrolled] = useState(false);
    const location = useLocation();

    useEffect(() => {
        const handleScroll = () => {
            setIsScrolled(window.scrollY > 20);
        };

        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const navLinks = [
        { name: 'Dashboard', path: '/dashboard' },
        { name: 'Scan', path: '/scan' },
        { name: 'History', path: '/history' },
        { name: 'Learn', path: '/learn' },
        { name: 'Docs', path: '/docs' },
    ];

    const isActive = (path: string) => location.pathname === path;

    return (
        <nav
            className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${isScrolled
                    ? 'bg-bg-primary/95 backdrop-blur-md shadow-lg border-b border-border-primary'
                    : 'bg-transparent'
                }`}
        >
            <Container>
                <div className="flex items-center justify-between h-20">
                    {/* Logo */}
                    <Link to="/" className="flex items-center gap-3 group">
                        <div className="w-10 h-10 bg-gradient-to-br from-accent-green to-accent-blue rounded-lg flex items-center justify-center group-hover:shadow-glow-green transition-all duration-300">
                            <span className="text-bg-primary font-bold text-xl font-mono">SW</span>
                        </div>
                        <div className="flex flex-col">
                            <span className="text-xl font-heading font-bold text-text-primary">
                                SafeWeb AI
                            </span>
                            <span className="text-xs text-text-tertiary font-mono">
                                Vulnerability Scanner
                            </span>
                        </div>
                    </Link>

                    {/* Navigation Links */}
                    <div className="hidden md:flex items-center gap-1">
                        {navLinks.map((link) => (
                            <Link
                                key={link.path}
                                to={link.path}
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${isActive(link.path)
                                        ? 'text-accent-green bg-accent-green/10'
                                        : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                                    }`}
                            >
                                {link.name}
                            </Link>
                        ))}
                    </div>

                    {/* Auth Buttons */}
                    <div className="flex items-center gap-3">
                        <Link to="/login">
                            <Button variant="ghost" size="sm">
                                Sign In
                            </Button>
                        </Link>
                        <Link to="/register">
                            <Button variant="primary" size="sm">
                                Get Started
                            </Button>
                        </Link>
                    </div>
                </div>
            </Container>
        </nav>
    );
}
