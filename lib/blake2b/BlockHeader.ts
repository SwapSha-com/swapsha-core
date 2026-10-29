/**
 * Bitcoin Knots block headers on both sides of the BLAKE2b fork.
 *
 * v1 (80 bytes): the original header, hashed with double SHA-256.
 * v2 (164 bytes): flagged by bit 31 of the version, hashed with BLAKE2b-256
 * through the tagged pre-hashes in src/primitives/block.cpp
 * (bitcoinknots/bitcoin v29.4.1.knots20260508). Required from the fork height.
 *
 * Verified against src/test/data/block_header_v2.json (all four ASIC profiles)
 * and against live headers from both regtest chains.
 */
import { blake2b } from '@noble/hashes/blake2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { hex } from '@scure/base';

export const HEADER_V1_SIZE = 80;
export const HEADER_V2_SIZE = 164;
export const VERSION_HEADER_V2_FLAG = 0x80000000;
const FLAG_USE_TIME_OFFSET = 4;

/** Fork block on the BLAKE2b mainnet chain (Blueprint 1.1). */
export const MAINNET_FORK = {
  height: 961_640,
  hash: '0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb',
};
export const TESTNET4_FORK_HEIGHT = 150_308;

/**
 * Byte arrays are kept exactly as they appear on the wire (Bitcoin's internal
 * little-endian order), so a hash written as hex for display is reversed.
 */
export type BlockHeader = {
  isV2: boolean;
  /** Version without the v2 flag */
  version: number;
  prevBlock: Uint8Array;
  merkleRoot: Uint8Array;
  /** Real block time, with the time offset applied when the flag says so */
  time: number;
  bits: number;
  nonce: number;
  // v2 only (zero / empty on v1)
  nonce2: number;
  nonce3: number;
  extranonce: Uint8Array;
  timeOffset: number;
  txCount: number;
  flags: number;
  xorKeyMaskClearBits: number;
  xorKey: Uint8Array;
  height: number;
  mmRhs: Uint8Array;
};

const tagged = (tag: string, ...data: Uint8Array[]): Uint8Array => {
  const t = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(t, t, ...data));
};

const u8 = (n: number) => new Uint8Array([n & 0xff]);
const u16 = (n: number) => {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
};
const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
};
const i32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setInt32(0, n, true);
  return b;
};
const reverse = (b: Uint8Array) => Uint8Array.from(b).reverse();
const isZero = (b: Uint8Array) => b.every((x) => x === 0);

const timeOnWire = (h: BlockHeader): number =>
  h.flags & FLAG_USE_TIME_OFFSET ? (h.time - h.timeOffset) >>> 0 : h.time;

export const parseBlockHeader = (raw: Uint8Array | string): BlockHeader => {
  const b = typeof raw === 'string' ? hex.decode(raw) : raw;
  if (b.length < HEADER_V1_SIZE) throw new Error('header too short');
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);

  const fullVersion = v.getUint32(0, true);
  const isV2 = (fullVersion & VERSION_HEADER_V2_FLAG) !== 0;
  const expected = isV2 ? HEADER_V2_SIZE : HEADER_V1_SIZE;
  if (b.length !== expected) {
    throw new Error(
      `${isV2 ? 'v2' : 'v1'} header must be ${expected} bytes, got ${b.length}`,
    );
  }

  const header: BlockHeader = {
    isV2,
    version: (fullVersion & ~VERSION_HEADER_V2_FLAG) | 0,
    prevBlock: b.slice(4, 36),
    merkleRoot: b.slice(36, 68),
    time: v.getUint32(68, true),
    bits: v.getUint32(72, true),
    nonce: v.getUint32(76, true),
    nonce2: 0,
    nonce3: 0,
    extranonce: new Uint8Array(16),
    timeOffset: 0,
    txCount: 0,
    flags: 0,
    xorKeyMaskClearBits: 0,
    xorKey: new Uint8Array(16),
    height: 0,
    mmRhs: new Uint8Array(32),
  };

  if (isV2) {
    header.nonce2 = v.getUint32(80, true);
    header.nonce3 = v.getUint32(84, true);
    header.extranonce = b.slice(88, 104);
    header.timeOffset = v.getUint32(104, true);
    header.txCount = v.getUint16(108, true);
    header.flags = b[110];
    header.xorKeyMaskClearBits = b[111];
    header.xorKey = b.slice(112, 128);
    header.height = v.getInt32(128, true);
    header.mmRhs = b.slice(132, 164);
    if (header.flags & FLAG_USE_TIME_OFFSET) {
      header.time = (header.time + header.timeOffset) >>> 0;
    }
  }

  return header;
};

export const serializeBlockHeader = (h: BlockHeader): Uint8Array => {
  const base = concatBytes(
    u32((h.isV2 ? VERSION_HEADER_V2_FLAG : 0) | (h.version & 0x7fffffff)),
    h.prevBlock,
    h.merkleRoot,
    u32(timeOnWire(h)),
    u32(h.bits),
    u32(h.nonce),
  );
  if (!h.isV2) return base;
  return concatBytes(
    base,
    u32(h.nonce2),
    u32(h.nonce3),
    h.extranonce,
    u32(h.timeOffset),
    u16(h.txCount),
    u8(h.flags),
    u8(h.xorKeyMaskClearBits),
    h.xorKey,
    i32(h.height),
    h.mmRhs,
  );
};

/** Block hash in wire order. Use blockHashHex for the usual display form. */
export const blockHash = (h: BlockHeader): Uint8Array => {
  if (!h.isV2) {
    return sha256(sha256(serializeBlockHeader(h)));
  }

  const zeros16 = new Uint8Array(16);
  const prevDisplay = reverse(h.prevBlock);

  const xorKeyHash = tagged('Bitcoin block hash PoW XOR key', h.xorKey);

  const mask = new Uint8Array(32);
  if (!isZero(h.xorKey)) {
    mask.set(tagged('Bitcoin block hash PoW XOR mask', h.xorKey));
    const clearBytes = Math.floor(h.xorKeyMaskClearBits / 8);
    mask.fill(0, 0, Math.min(clearBytes, 32));
    if (clearBytes < 32)
      mask[clearBytes] &= 0xff >> (h.xorKeyMaskClearBits % 8);
  }

  const prevHidden = tagged('Bitcoin prevblock header, hashed', prevDisplay);

  const h1 = tagged(
    'Bitcoin block header 1',
    u32((h.isV2 ? VERSION_HEADER_V2_FLAG : 0) | (h.version & 0x7fffffff)),
    prevDisplay,
    i32(h.height),
    h.merkleRoot,
    u32(timeOnWire(h)),
    u8(0), // reserved for 40-bit time
    u32(h.bits),
    u32(h.txCount),
    u8(h.flags),
    u8(h.xorKeyMaskClearBits),
    xorKeyHash,
  );

  const h2 = tagged('Merge-mining hook', h1, zeros16, zeros16, h.mmRhs);

  const first = blake2b(concatBytes(u32(0), h2, h.extranonce), { dkLen: 32 });

  const nonces = [
    u32(h.nonce),
    u32(h.nonce2),
    u32(h.timeOffset),
    u32(h.nonce3),
  ];
  let asicInput: Uint8Array;
  switch (h.flags & 3) {
    case 3:
      asicInput = concatBytes(new Uint8Array(32 + 48), h2, ...nonces, first);
      break;
    case 2:
      asicInput = concatBytes(new Uint8Array(48), h2, ...nonces, first);
      break;
    case 1:
      asicInput = concatBytes(
        u32(h.nonce),
        u32(h.nonce2),
        u32(h.nonce3),
        u32(h.timeOffset),
        first,
        h2,
      );
      break;
    default: {
      const hidden = Uint8Array.from(prevHidden);
      hidden.fill(0, 0, 6);
      asicInput = concatBytes(hidden, ...nonces, first);
    }
  }

  const second = blake2b(asicInput, { dkLen: 32 });
  // Knots writes (second XOR mask) into the hash back to front, so the display
  // form is second XOR mask as-is and the wire form is its reverse.
  return reverse(second.map((x, i) => x ^ mask[i]));
};

export const blockHashHex = (h: BlockHeader): string =>
  hex.encode(reverse(blockHash(h)));

/** Expand compact nBits to a 256-bit target. */
export const targetFromBits = (bits: number): bigint => {
  const exponent = bits >>> 24;
  const mantissa = BigInt(bits & 0x007fffff);
  if (bits & 0x00800000) throw new Error('negative target');
  return exponent <= 3
    ? mantissa >> BigInt(8 * (3 - exponent))
    : mantissa << BigInt(8 * (exponent - 3));
};

/** True when the header's hash meets its own nBits target. */
export const checkProofOfWork = (h: BlockHeader): boolean => {
  const target = targetFromBits(h.bits);
  if (target === 0n) return false;
  return BigInt(`0x${blockHashHex(h)}`) <= target;
};
