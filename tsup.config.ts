import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'adapters/prisma': 'src/adapters/prisma.ts',
    'adapters/email': 'src/adapters/email.ts',
    'adapters/oauth': 'src/adapters/oauth/index.ts',
    'transport/express': 'src/transport/express.ts',
    server: 'src/server.ts',
  },
  format: ['esm', 'cjs'],
  dts: false,
  splitting: false,
  clean: true,
  target: 'node20',
  outDir: 'dist',
  outExtension({ format }) {
    return { js: format === 'cjs' ? '.cjs' : '.js' };
  },
});