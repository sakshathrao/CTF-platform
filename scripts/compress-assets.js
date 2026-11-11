#!/usr/bin/env node
import { createBrotliCompress, createGzip, constants as zlibConstants } from 'node:zlib';
import { readdir, stat, readFile, writeFile, mkdir, copyFile, unlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, extname, basename, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const projectRoot = join(__filename, '..', '..');
const distDir = join(projectRoot, 'dist');

// Skip binary, media, and already-compressed file formats
const skipExtensions = new Set([
  '.iso', '.img', '.bin', '.wasm', '.bz2', '.xz', '.zip', '.br', '.gz',
  '.png', '.jpg', '.jpeg', '.webp', '.gif', '.ico', '.mp4', '.webm', '.woff', '.woff2',
  '.pcap', '.pdf', '.wav', '.mbox', '.tar', '.tgz'
]);

// Suitable text and code formats for precompression
const compressibleExtensions = new Set([
  '.html', '.css', '.js', '.mjs', '.json', '.svg', '.xml', '.txt', '.map'
]);

async function copyV86Assets() {
  const v86SrcDir = join(projectRoot, 'node_modules/v86/build');
  const v86DstDir = join(distDir, 'node_modules/v86/build');

  if (existsSync(v86SrcDir)) {
    await mkdir(v86DstDir, { recursive: true });
    for (const file of ['libv86.js', 'libv86.mjs', 'v86.wasm', 'v86-fallback.wasm']) {
      const src = join(v86SrcDir, file);
      const dst = join(v86DstDir, file);
      if (existsSync(src)) {
        await copyFile(src, dst);
        console.log(`Copied v86 runtime asset: ${file} -> dist/node_modules/v86/build/`);
      }
    }
  }
}

async function compressFile(filePath) {
  const ext = extname(filePath).toLowerCase();
  
  // Clean up any old precompressed versions of skipped formats
  if (skipExtensions.has(ext) || !compressibleExtensions.has(ext)) {
    if (existsSync(filePath + '.br')) await unlink(filePath + '.br').catch(() => {});
    if (existsSync(filePath + '.gz')) await unlink(filePath + '.gz').catch(() => {});
    return;
  }
  
  const s = await stat(filePath);
  if (s.size > 10 * 1024 * 1024) return;
  if (s.size < 64) return; // Skip tiny files
  
  const content = await readFile(filePath);
  const base = filePath;
  
  const br = await new Promise((resolve, reject) => {
    const c = createBrotliCompress({
      params: {
        [zlibConstants.BROTLI_PARAM_QUALITY]: 11,
        [zlibConstants.BROTLI_PARAM_SIZE_HINT]: content.length
      }
    });
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
  
  // Only write precompressed files if compression actually reduced size
  if (br.length < content.length) {
    await writeFile(base + '.br', br);
  }
  if (gz.length < content.length) {
    await writeFile(base + '.gz', gz);
  }
  
  console.log(`${basename(filePath)} (${content.length} bytes)`);
  if (br.length < content.length) {
    console.log(`  .br: ${br.length} bytes (${(content.length / br.length).toFixed(2)}x)`);
  }
  if (gz.length < content.length) {
    console.log(`  .gz: ${gz.length} bytes (${(content.length / gz.length).toFixed(2)}x)`);
  }
}

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules') continue; // don't compress raw node_modules in dist
      await walk(p);
    } else if (e.isFile()) {
      await compressFile(p);
    }
  }
}

console.log('Copying runtime dependencies to dist...');
await copyV86Assets();
console.log('Compressing text/code assets in:', distDir);
await walk(distDir);
console.log('Asset optimization complete.');
