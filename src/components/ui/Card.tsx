import type { CardProps } from '@types/components';

export default function Card({
    children,
    className = '',
    variant = 'default',
    hover = false,
    glow = 'none',
    id,
}: CardProps) {
    const baseClasses = 'rounded-lg transition-all duration-300';

    const variants = {
        default: 'bg-bg-card border border-border-primary',
        glass: 'bg-bg-card/50 backdrop-blur-sm border border-border-primary/50',
        bordered: 'bg-transparent border-2 border-border-secondary',
    };

    const hoverClasses = hover
        ? 'hover:shadow-card-hover hover:-translate-y-1 cursor-pointer'
        : '';

    const glowClasses = {
        none: '',
        green: 'shadow-glow-green',
        blue: 'shadow-glow-blue',
    };

    return (
        <div
            id={id}
            className={`${baseClasses} ${variants[variant]} ${hoverClasses} ${glowClasses[glow]} ${className}`}
        >
            {children}
        </div>
    );
}
