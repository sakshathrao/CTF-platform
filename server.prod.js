import http from "node:http";
import { readFileSync, statSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.join(__dirname, "dist");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".wasm": "application/wasm",
  ".bin": "application/octet-stream",
  ".img": "application/octet-stream",
  ".iso": "application/x-iso9660-image",
};

const SERVER_HOST = "0.0.0.0";
const SERVER_PORT = 3001;

function getContentType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return MIME_TYPES[ext] || "application/octet-stream";
}

function getCompressedPath(filePath, encoding) {
  if (encoding === "br") {
    return filePath + ".br";
  } else if (encoding === "gzip") {
    return filePath + ".gz";
  }
  return null;
}

function parseAcceptEncoding(header) {
  if (!header) return "none";
  
  const encodings = header.split(",").map(e => e.trim().split(";")[0].toLowerCase());
  
  // Prefer Brotli over gzip
  if (encodings.includes("br")) return "br";
  if (encodings.includes("gzip")) return "gzip";
  if (encodings.includes("deflate")) return "deflate";
  
  return "none";
}

const server = http.createServer(async (req, res) => {
  // Security headers
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "0");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Content-Security-Policy", 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' blob: data:; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: blob:; " +
    "connect-src 'self' ws: wss:; " +
    "font-src 'self' data:; " +
    "object-src 'none'; " +
    "frame-ancestors 'none'");
  
  // CORS
  const origin = req.headers.origin;
  if (origin) {
    try {
      const originURL = new URL(origin);
      const serverHost = req.headers.host.split(":")[0];
      if (originURL.protocol === "http:" && originURL.hostname === serverHost) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Access-Control-Allow-Credentials", "true");
        res.setHeader("Vary", "Origin");
      }
    } catch {}
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  
  // Handle OPTIONS
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  
  // Only handle GET for static files
  if (req.method !== "GET") {
    res.writeHead(405);
    res.end("Method Not Allowed");
    return;
  }
  
  // Decode URL to prevent path traversal
  let urlPath = decodeURIComponent(req.url.split("?")[0]);
  
  // Prevent directory traversal
  if (urlPath.includes("..") || urlPath.startsWith("/..")) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  
  // Remove leading slash and resolve
  let cleanPath = urlPath.startsWith("/") ? urlPath.substring(1) : urlPath;
  
  // Default to index.html for root
  if (cleanPath === "" || cleanPath === "/") {
    cleanPath = "main.html";
  }
  
  const filePath = path.join(distDir, cleanPath);
  
  // Verify the resolved path is within distDir
  const resolvedPath = path.resolve(filePath);
  if (!resolvedPath.startsWith(path.resolve(distDir) + path.sep) && resolvedPath !== path.resolve(distDir)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  
  try {
    // Check if file exists
    try {
      statSync(filePath);
    } catch {
      res.writeHead(404);
      res.end("Not Found");
      return;
    }
    
    const contentType = getContentType(filePath);
    
    // Check for precompressed versions
    const acceptEncoding = parseAcceptEncoding(req.headers["accept-encoding"]);
    const compressedPath = getCompressedPath(filePath, acceptEncoding);
    
    if (compressedPath && existsSync(compressedPath)) {
      res.setHeader("Content-Encoding", acceptEncoding === "br" ? "br" : "gzip");
      res.setHeader("Content-Type", contentType);
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      res.writeHead(200);
      const data = readFileSync(compressedPath);
      res.end(data);
      console.log(`Served ${cleanPath} (${acceptEncoding}, ${data.length} bytes)`);
      return;
    }
    
    // Fallback to uncompressed
    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    res.writeHead(200);
    const data = readFileSync(filePath);
    res.end(data);
    console.log(`Served ${cleanPath} (uncompressed, ${data.length} bytes)`);
  } catch (err) {
    console.error("Error serving file:", err);
    res.writeHead(500);
    res.end("Internal Server Error");
  }
});

server.listen(SERVER_PORT, SERVER_HOST, () => {
  console.log(`Production file server running on http://${SERVER_HOST}:${SERVER_PORT}`);
  console.log(`Serving: ${distDir}`);
  console.log(`\nContent negotiation: Brotli (.br) > gzip (.gz) > uncompressed`);
});
