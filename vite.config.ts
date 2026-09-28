import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({ plugins: [react()], server: { host: '127.0.0.1', port: 1420, strictPort: true }, clearScreen: false, test: { include: ['src/**/*.test.ts', 'src/**/*.test.tsx'], environment: 'jsdom', environmentOptions: { jsdom: { url: 'http://localhost/?preview=1' } }, globals: true } });
