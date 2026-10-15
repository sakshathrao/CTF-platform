/**
 * CTF Platform — Production Server Entry Point
 * 
 * Reconciled unified server that serves static production assets from dist/
 * with Brotli (.br) > gzip (.gz) > uncompressed content negotiation,
 * security headers, full CTF API endpoints, and authenticated WebSockets.
 * Bound to loopback (127.0.0.1) only.
 */

process.env.NODE_ENV = process.env.NODE_ENV || "production";

export * from "./server.js";
