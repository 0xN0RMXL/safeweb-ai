import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./src', import.meta.url)),
            '@components': fileURLToPath(new URL('./src/components', import.meta.url)),
            '@pages': fileURLToPath(new URL('./src/pages', import.meta.url)),
            '@utils': fileURLToPath(new URL('./src/utils', import.meta.url)),
            '@types': fileURLToPath(new URL('./src/types', import.meta.url)),
            '@assets': fileURLToPath(new URL('./src/assets', import.meta.url)),
            '@services': fileURLToPath(new URL('./src/services', import.meta.url)),
            '@contexts': fileURLToPath(new URL('./src/contexts', import.meta.url)),
        },
    },
    server: {
        watch: {
            ignored: ['**/*.pptx', '**/*.pdf', '**/backend/**', '**/safeweb-ai-refactor/**'],
        },
        proxy: {
            '/api': {
                target: 'http://127.0.0.1:8000',
                changeOrigin: true,
            },
        },
    },
    build: {
        rollupOptions: {
            output: {
                manualChunks: {
                    // Core vendor libs — cached separately, never change with app deploys
                    'vendor-react': ['react', 'react-dom'],
                    'vendor-router': ['react-router-dom'],
                    'vendor-axios': ['axios'],
                },
            },
        },
        // Raise the warning threshold now that chunks are split
        chunkSizeWarningLimit: 400,
    },
});
