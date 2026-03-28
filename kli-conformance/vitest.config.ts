import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 120_000,
    hookTimeout: 60_000,
    pool: 'forks',
    include: ['tests/**/*.test.ts'],
  },
});
