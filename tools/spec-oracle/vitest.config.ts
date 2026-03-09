import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['output/cesr-laws.property.ts'],
  },
});
