#!/usr/bin/env node
/**
 * Generate PhishGuard PNG icons with no external dependencies.
 * Draws a supersampled shield with a check mark and writes 16/32/48/128 px PNGs.
 *
 * Usage: node scripts/generate-icons.mjs
 */
import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "extension", "icons");

/* ------------------------------- geometry -------------------------------- */

// Shield silhouette in a 0..1 coordinate space (clockwise).
const SHIELD = [
  [0.5, 0.055],
  [0.885, 0.155],
  [0.885, 0.5],
  [0.845, 0.62],
  [0.765, 0.735],
  [0.655, 0.835],
  [0.5, 0.945],
  [0.345, 0.835],
  [0.235, 0.735],
  [0.155, 0.62],
  [0.115, 0.5],
  [0.115, 0.155],
];

const CHECK = [
  [0.325, 0.5],
  [0.45, 0.63],
  [0.69, 0.35],
];

const CHECK_WIDTH = 0.072;

function pointInPolygon(x, y, polygon) {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const xi = polygon[i][0];
    const yi = polygon[i][1];
    const xj = polygon[j][0];
    const yj = polygon[j][1];
    const intersect = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

function distanceToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const lengthSq = dx * dx + dy * dy;
  let t = lengthSq > 0 ? ((px - ax) * dx + (py - ay) * dy) / lengthSq : 0;
  t = Math.max(0, Math.min(1, t));
  const cx = ax + t * dx;
  const cy = ay + t * dy;
  return Math.hypot(px - cx, py - cy);
}

function checkDistance(x, y) {
  let best = Infinity;
  for (let i = 0; i < CHECK.length - 1; i++) {
    const [ax, ay] = CHECK[i];
    const [bx, by] = CHECK[i + 1];
    best = Math.min(best, distanceToSegment(x, y, ax, ay, bx, by));
  }
  return best;
}

// Vertical gradient between two RGB colours.
const TOP = [0x5e, 0xc8, 0xfb];
const BOTTOM = [0x0b, 0x7f, 0xc4];
const CHECK_COLOR = [0x04, 0x12, 0x1f];

function colorAt(x, y, isCheck) {
  if (isCheck) return CHECK_COLOR;
  const t = Math.max(0, Math.min(1, (y - 0.05) / 0.9));
  return [
    Math.round(TOP[0] + (BOTTOM[0] - TOP[0]) * t),
    Math.round(TOP[1] + (BOTTOM[1] - TOP[1]) * t),
    Math.round(TOP[2] + (BOTTOM[2] - TOP[2]) * t),
  ];
}

function renderRgba(size) {
  const samples = size <= 32 ? 6 : 4;
  const pixels = Buffer.alloc(size * size * 4);

  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;

      for (let sy = 0; sy < samples; sy++) {
        for (let sx = 0; sx < samples; sx++) {
          const x = (px + (sx + 0.5) / samples) / size;
          const y = (py + (sy + 0.5) / samples) / size;
          if (!pointInPolygon(x, y, SHIELD)) continue;
          const isCheck = checkDistance(x, y) <= CHECK_WIDTH;
          const [cr, cg, cb] = colorAt(x, y, isCheck);
          r += cr;
          g += cg;
          b += cb;
          a += 1;
        }
      }

      const total = samples * samples;
      const offset = (py * size + px) * 4;
      if (a === 0) {
        pixels[offset] = 0;
        pixels[offset + 1] = 0;
        pixels[offset + 2] = 0;
        pixels[offset + 3] = 0;
      } else {
        // Premultiplied averaging keeps edges from picking up dark fringes.
        pixels[offset] = Math.round(r / a);
        pixels[offset + 1] = Math.round(g / a);
        pixels[offset + 2] = Math.round(b / a);
        pixels[offset + 3] = Math.round((a / total) * 255);
      }
    }
  }

  return pixels;
}

/* ---------------------------------- PNG ---------------------------------- */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let c = 0xffffffff;
  for (let i = 0; i < buffer.length; i++) {
    c = CRC_TABLE[(c ^ buffer[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeBuffer = Buffer.from(type, "ascii");
  const body = Buffer.concat([typeBuffer, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([length, body, crc]);
}

function encodePng(size, rgba) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: truecolour with alpha
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (stride + 1)] = 0; // filter type: none
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  const idat = deflateSync(raw, { level: 9 });

  return Buffer.concat([
    signature,
    chunk("IHDR", ihdr),
    chunk("IDAT", idat),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/* ---------------------------------- main --------------------------------- */

mkdirSync(outDir, { recursive: true });

let total = 0;
for (const size of [16, 32, 48, 128]) {
  const rgba = renderRgba(size);
  const png = encodePng(size, rgba);
  const target = join(outDir, `icon${size}.png`);
  writeFileSync(target, png);
  total += png.length;
  console.log(`wrote ${target} (${size}x${size}, ${png.length} bytes)`);
}

console.log(`done: ${total} bytes across 4 icons`);
