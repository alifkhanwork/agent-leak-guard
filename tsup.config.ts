import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
    },
    format: ['cjs', 'esm'],
    dts: true,
    clean: true,
    sourcemap: true,
    minify: false,
  },
  {
    entry: {
      cli: 'src/cli/index.ts',
    },
    format: ['cjs'],
    dts: false,
    clean: false,
    banner: {
      js: '#!/usr/bin/env node',
    },
  },
]);
