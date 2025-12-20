/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                // Background colors
                'bg-primary': '#050607',
                'bg-secondary': '#0A0C0E',
                'bg-tertiary': '#0F1113',
                'bg-card': '#12151A',
                'bg-hover': '#1A1D23',

                // Accent colors
                'accent-green': '#00FF88',
                'accent-green-hover': '#00E67A',
                'accent-blue': '#3AA9FF',
                'accent-blue-hover': '#2E95E8',

                // Status colors
                'status-critical': '#FF3B3B',
                'status-high': '#FF8A3D',
                'status-medium': '#FFD93D',
                'status-low': '#6BCF7F',
                'status-info': '#3AA9FF',

                // Text colors
                'text-primary': '#FFFFFF',
                'text-secondary': '#B0B8C1',
                'text-tertiary': '#6B7280',
                'text-muted': '#4B5563',

                // Border colors
                'border-primary': '#1F2937',
                'border-secondary': '#374151',
                'border-accent': '#00FF88',
            },
            fontFamily: {
                'sans': ['Inter', 'system-ui', 'sans-serif'],
                'heading': ['Space Grotesk', 'Inter', 'sans-serif'],
                'mono': ['JetBrains Mono', 'Fira Code', 'monospace'],
            },
            maxWidth: {
                'container': '1200px',
                'content': '720px',
            },
            spacing: {
                'header': '80px',
            },
            animation: {
                'glow': 'glow 2s ease-in-out infinite alternate',
                'float': 'float 3s ease-in-out infinite',
                'terminal-blink': 'blink 1s step-end infinite',
            },
            keyframes: {
                glow: {
                    '0%': { boxShadow: '0 0 5px rgba(0, 255, 136, 0.2), 0 0 10px rgba(0, 255, 136, 0.1)' },
                    '100%': { boxShadow: '0 0 10px rgba(0, 255, 136, 0.4), 0 0 20px rgba(0, 255, 136, 0.2)' },
                },
                float: {
                    '0%, 100%': { transform: 'translateY(0px)' },
                    '50%': { transform: 'translateY(-10px)' },
                },
                blink: {
                    '0%, 100%': { opacity: '1' },
                    '50%': { opacity: '0' },
                },
            },
            boxShadow: {
                'glow-green': '0 0 15px rgba(0, 255, 136, 0.3)',
                'glow-blue': '0 0 15px rgba(58, 169, 255, 0.3)',
                'card': '0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2)',
                'card-hover': '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3)',
            },
        },
    },
    plugins: [],
}
