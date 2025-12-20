import type { ButtonProps } from '@types/components';

export default function Button({
    variant = 'primary',
    size = 'md',
    isLoading = false,
    leftIcon,
    rightIcon,
    className = '',
    children,
    disabled,
    ...props
}: ButtonProps) {
    const baseClasses = 'inline-flex items-center justify-center gap-2 font-medium transition-all duration-200 focus-visible-custom disabled:opacity-50 disabled:cursor-not-allowed';

    const variants = {
        primary: 'bg-accent-green text-bg-primary hover:bg-accent-green-hover hover:shadow-glow-green',
        secondary: 'bg-accent-blue text-text-primary hover:bg-accent-blue-hover hover:shadow-glow-blue',
        outline: 'border-2 border-accent-green text-accent-green hover:bg-accent-green hover:text-bg-primary',
        ghost: 'text-accent-green hover:bg-accent-green/10',
        danger: 'bg-status-critical text-text-primary hover:bg-status-critical/80',
    };

    const sizes = {
        sm: 'px-3 py-1.5 text-sm rounded',
        md: 'px-5 py-2.5 text-base rounded-lg',
        lg: 'px-7 py-3.5 text-lg rounded-lg',
    };

    return (
        <button
            className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${className}`}
            disabled={disabled || isLoading}
            {...props}
        >
            {isLoading ? (
                <>
                    <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>Loading...</span>
                </>
            ) : (
                <>
                    {leftIcon && <span className="flex-shrink-0">{leftIcon}</span>}
                    {children}
                    {rightIcon && <span className="flex-shrink-0">{rightIcon}</span>}
                </>
            )}
        </button>
    );
}
