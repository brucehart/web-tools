import { copyFileSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const runtimeFiles = [
  {
    from: path.join(rootDir, 'node_modules', '@jsquash', 'avif', 'meta.js'),
    to: path.join(rootDir, 'public', 'vendor', 'jsquash-avif', 'meta.js'),
  },
  {
    from: path.join(rootDir, 'node_modules', '@jsquash', 'avif', 'utils.js'),
    to: path.join(rootDir, 'public', 'vendor', 'jsquash-avif', 'utils.js'),
  },
  {
    from: path.join(rootDir, 'node_modules', '@jsquash', 'avif', 'codec', 'enc', 'avif_enc.js'),
    to: path.join(rootDir, 'public', 'vendor', 'jsquash-avif', 'codec', 'enc', 'avif_enc.js'),
  },
  {
    from: path.join(rootDir, 'node_modules', '@jsquash', 'avif', 'codec', 'enc', 'avif_enc.wasm'),
    to: path.join(rootDir, 'public', 'vendor', 'jsquash-avif', 'codec', 'enc', 'avif_enc.wasm'),
  },
  {
    from: path.join(rootDir, 'node_modules', '@jsquash', 'avif', 'codec', 'enc', 'avif_enc_mt.js'),
    to: path.join(rootDir, 'public', 'vendor', 'jsquash-avif', 'codec', 'enc', 'avif_enc_mt.js'),
  },
  {
    from: path.join(rootDir, 'node_modules', '@jsquash', 'avif', 'codec', 'enc', 'avif_enc_mt.wasm'),
    to: path.join(rootDir, 'public', 'vendor', 'jsquash-avif', 'codec', 'enc', 'avif_enc_mt.wasm'),
  },
  {
    from: path.join(rootDir, 'node_modules', '@jsquash', 'avif', 'codec', 'enc', 'avif_enc_mt.worker.mjs'),
    to: path.join(rootDir, 'public', 'vendor', 'jsquash-avif', 'codec', 'enc', 'avif_enc_mt.worker.mjs'),
  },
  {
    from: path.join(rootDir, 'node_modules', 'wasm-feature-detect', 'dist', 'esm', 'index.js'),
    to: path.join(rootDir, 'public', 'vendor', 'wasm-feature-detect', 'index.js'),
  },
];

for (const outputDir of [
  path.join(rootDir, 'public', 'vendor', 'jsquash-avif'),
  path.join(rootDir, 'public', 'vendor', 'wasm-feature-detect'),
]) {
  rmSync(outputDir, { force: true, recursive: true });
}

for (const file of runtimeFiles) {
  mkdirSync(path.dirname(file.to), { recursive: true });
  copyFileSync(file.from, file.to);
}
