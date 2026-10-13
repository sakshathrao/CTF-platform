#!/usr/bin/env node
import { createBrotliCompress } from 'node:zlib';
import { createGzip } from 'node:zlib';
import { readdir, stat, readFile, writeFile } from 'node:fs/promises';
import { join, extname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const projectRoot = join(__filename, '..', '..');
const distDir = join(projectRoot, 'dist');

const zlib = await import('node:zlib');
const skipExtensions = new Set(['.iso', '.img', '.bin', '.wasm', '.bz2', '.xz', '.zip', '.br', '.gz']);

async function compressFile(filePath) {
  const ext = extname(filePath).toLowerCase();
  if (skipExtensions.has(ext)) return;
  
  const s = await stat(filePath);
  if (s.size > 10 * 1024 * 1024) return;
  if (s.size < 100) return;
  
  const content = await readFile(filePath);
  const base = filePath;
  
  const br = await new Promise((resolve, reject) => {
    const c = createBrotliCompress({ params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 } });
    const chunks = [];
    c.on('data', d => chunks.push(d));
    c.on('end', () => resolve(Buffer.concat(chunks)));
    c.on('error', reject);
    c.write(content);
    c.end();
  });
  
  const gz = await new Promise((resolve, reject) => {
    const c = createGzip({ level: 9 });
    const chunks = [];
    c.on('data', d => chunks.push(d));
    c.on('end', () => resolve(Buffer.concat(chunks)));
    c.on('error', reject);
    c.write(content);
    c.end();
  });
  
  await writeFile(base + '.br', br);
  await writeFile(base + '.gz', gz);
  
  console.log(`${basename(filePath)} (${content.length} bytes)`);
  console.log(`  .br: ${br.length} bytes (${(content.length/br.length).toFixed(2)}x)`);
  console.log(`  .gz: ${gz.length} bytes (${(content.length/gz.length).toFixed(2)}x)`);
}

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) await walk(p);
    else if (e.isFile()) await compressFile(p);
  }
}

console.log('Compressing:', distDir);
await walk(distDir);
console.log('Done.');
