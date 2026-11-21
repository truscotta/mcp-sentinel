import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    globals: false,
    testTimeout: 10000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/types/**/*.ts', 'src/cli/bin.ts', 'src/index.ts'],
      thresholds: {
        lines: 75,
        functions: 90,
        statements: 75,
        branches: 65,
      },
    },
  },
});
