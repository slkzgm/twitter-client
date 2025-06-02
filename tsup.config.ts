import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  outDir: 'dist',
  tsconfig: 'tsconfig.build.json',
  sourcemap: true,
  clean: true,
  format: ['esm'], // Building ESM
  dts: true,       // Generates index.d.ts
  external: [
    'fs',
    'path',
    'https',
    'http',
    'agentkeepalive'
  ],
});
