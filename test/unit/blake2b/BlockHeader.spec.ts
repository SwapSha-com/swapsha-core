import { hex } from '@scure/base';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  type BlockHeader,
  blockHashHex,
  parseBlockHeader,
  serializeBlockHeader,
} from '../../../lib/blake2b/BlockHeader.ts';

// Vectors from bitcoinknots/bitcoin@v29.4.1.knots20260508
// src/test/data/block_header_v2.json, one per ASIC profile and a masked hash.
type Vector = {
  name: string;
  fields: Record<string, number | string>;
  serialized: string;
  block_hash: string;
  asic_profile: number;
};
const vectors = (
  JSON.parse(readFileSync(join(__dirname, 'block_header_v2.json'), 'utf8')) as {
    headers: Vector[];
  }
).headers;

// The JSON gives hashes and 128-bit fields in display order.
const fromDisplay = (s: string) => hex.decode(s).reverse();

const fromFields = (f: Vector['fields']): BlockHeader => ({
  isV2: true,
  version: f.nVersion as number,
  prevBlock: fromDisplay(f.hashPrevBlock as string),
  merkleRoot: fromDisplay(f.hashMerkleRoot as string),
  time: f.nTime as number,
  bits: f.nBits as number,
  nonce: f.nNonce as number,
  nonce2: f.m_nonce2 as number,
  nonce3: f.m_nonce3 as number,
  extranonce: fromDisplay(f.m_extranonce as string),
  timeOffset: f.m_time_offset as number,
  txCount: f.m_txcount as number,
  flags: f.m_flags as number,
  xorKeyMaskClearBits: f.m_xor_key_mask_clear_bits as number,
  xorKey: fromDisplay(f.m_xor_key as string),
  height: f.m_height as number,
  mmRhs: fromDisplay(f.m_mm_rhs as string),
});

describe('BLAKE2b block header v2', () => {
  test.each(vectors.map((v) => [v.name, v] as const))('%s', (_name, v) => {
    const header = fromFields(v.fields);
    expect(header.flags & 3).toEqual(v.asic_profile);

    const encoded = serializeBlockHeader(header);
    expect(encoded).toHaveLength(164);
    expect(hex.encode(encoded)).toEqual(v.serialized);
    expect(blockHashHex(header)).toEqual(v.block_hash);

    const decoded = parseBlockHeader(v.serialized);
    expect(decoded.time).toEqual(header.time);
    expect(blockHashHex(decoded)).toEqual(v.block_hash);
  });

  test('v1 header hashes with double SHA-256 (Bitcoin genesis)', () => {
    const genesis =
      '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c';
    expect(blockHashHex(parseBlockHeader(genesis))).toEqual(
      '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    );
  });

  test('rejects a v2-flagged header of the wrong length', () => {
    expect(() => parseBlockHeader(vectors[0].serialized.slice(0, 160))).toThrow(
      'v2 header must be 164 bytes',
    );
  });
});
