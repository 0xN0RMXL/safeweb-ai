import { useState, useEffect, useRef } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import Button from '@components/ui/Button';
import Container from '@components/ui/Container';
import GlitchText from '@components/ui/GlitchText';
import { useAuth } from '@/contexts/AuthContext';

export default function Navbar() {
    const [isScrolled, setIsScrolled] = useState(false);
    const [showUserMenu, setShowUserMenu] = useState(false);
    const [showMobileMenu, setShowMobileMenu] = useState(false);
    const menuRef = useRef<HTMLDivElement>(null);
    const mobileMenuRef = useRef<HTMLDivElement>(null);
    const location = useLocation();
    const navigate = useNavigate();
    const { user, isAuthenticated, logout } = useAuth();

    // Close mobile menu on route change
    useEffect(() => {
        setShowMobileMenu(false);
    }, [location.pathname]);

    useEffect(() => {
        const handleScroll = () => {
            setIsScrolled(window.scrollY > 20);
        };

        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    // Close user menu on click outside
    useEffect(() => {
        const handleClickOutside = (e: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
                setShowUserMenu(false);
            }
        };
        if (showUserMenu) {
            document.addEventListener('mousedown', handleClickOutside);
        }
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [showUserMenu]);

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
                            <GlitchText as="span" className="text-xl font-heading font-bold text-text-primary" interval={10000}>
                                SafeWeb AI
                            </GlitchText>
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

                    {/* Mobile menu button */}
                    <button
                        onClick={() => setShowMobileMenu(!showMobileMenu)}
                        className="md:hidden p-2 rounded-lg text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors"
                        aria-label="Toggle menu"
                    >
                        {showMobileMenu ? (
                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        ) : (
                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                            </svg>
                        )}
                    </button>

                    {/* Auth Buttons */}
                    <div className="hidden md:flex items-center gap-3">
                        {isAuthenticated ? (
                            <div className="relative" ref={menuRef}>
                                <button
                                    onClick={() => setShowUserMenu(!showUserMenu)}
                                    className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-all duration-200"
                                >
                                    <div className="w-8 h-8 rounded-full bg-accent-green/20 flex items-center justify-center text-accent-green font-semibold text-sm">
                                        {user?.name?.charAt(0).toUpperCase() || 'U'}
                                    </div>
                                    <span className="hidden md:inline">{user?.name}</span>
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                    </svg>
                                </button>
                                {showUserMenu && (
                                    <div className="absolute right-0 top-full mt-2 w-48 bg-bg-card border border-border-primary rounded-lg shadow-xl py-2 z-50">
                                        <Link
                                            to="/profile"
                                            onClick={() => setShowUserMenu(false)}
                                            className="block px-4 py-2 text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover"
                                        >
                                            Profile
                                        </Link>
                                        {user?.role === 'admin' && (
                                            <Link
                                                to="/admin"
                                                onClick={() => setShowUserMenu(false)}
                                                className="block px-4 py-2 text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover"
                                            >
                                                Admin Panel
                                            </Link>
                                        )}
                                        <hr className="my-1 border-border-primary" />
                                        <button
                                            onClick={async () => {
                                                setShowUserMenu(false);
                                                await logout();
                                                navigate('/');
                                            }}
                                            className="block w-full text-left px-4 py-2 text-sm text-status-critical hover:bg-bg-hover"
                                        >
                                            Sign Out
                                        </button>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <>
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
                            </>
                        )}
                    </div>
                </div>
            </Container>

            {/* Mobile Menu Drawer */}
            {showMobileMenu && (
                <div ref={mobileMenuRef} className="md:hidden bg-bg-primary/95 backdrop-blur-md border-t border-border-primary">
                    <Container>
                        <div className="py-4 space-y-1">
                            {navLinks.map((link) => (
                                <Link
                                    key={link.path}
                                    to={link.path}
                                    className={`block px-4 py-3 rounded-lg text-sm font-medium transition-colors ${isActive(link.path)
                                        ? 'text-accent-green bg-accent-green/10'
                                        : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                                    }`}
                                >
                                    {link.name}
                                </Link>
                            ))}
                            <hr className="my-2 border-border-primary" />
                            {isAuthenticated ? (
                                <>
                                    <Link
                                        to="/profile"
                                        className="block px-4 py-3 rounded-lg text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-bg-hover"
                                    >
                                        Profile
                                    </Link>
                                    {user?.role === 'admin' && (
                                        <Link
                                            to="/admin"
                                            className="block px-4 py-3 rounded-lg text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-bg-hover"
                                        >
                                            Admin Panel
                                        </Link>
                                    )}
                                    <button
                                        onClick={async () => {
                                            setShowMobileMenu(false);
                                            await logout();
                                            navigate('/');
                                        }}
                                        className="block w-full text-left px-4 py-3 rounded-lg text-sm font-medium text-status-critical hover:bg-bg-hover"
                                    >
                                        Sign Out
                                    </button>
                                </>
                            ) : (
                                <div className="flex gap-3 px-4 pt-2">
                                    <Link to="/login" className="flex-1">
                                        <Button variant="ghost" size="sm" className="w-full">Sign In</Button>
                                    </Link>
                                    <Link to="/register" className="flex-1">
                                        <Button variant="primary" size="sm" className="w-full">Get Started</Button>
                                    </Link>
                                </div>
                            )}
                        </div>
                    </Container>
                </div>
            )}
        </nav>
    );
}
