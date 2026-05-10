import * as esbuild from 'esbuild';
import { readFileSync } from 'fs';

const format = process.argv[2]; // 'esm' or 'cjs'

if (!format || !['esm', 'cjs'].includes(format)) {
  console.error('Usage: node esbuild.mjs [esm|cjs]');
  process.exit(1);
}

const pkg = JSON.parse(readFileSync('./package.json', 'utf8'));
const external = [
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.peerDependencies || {}),
  'crypto',
  'node:crypto',
];

await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'node',
  target: 'node18',
  format,
  outdir: `dist/${format}`,
  external,
  sourcemap: true,
  minify: false, // Keep readable for security audits
  legalComments: 'inline',
});

console.log(`✓ Built ${format.toUpperCase()} output`);
