/**
 * Bitcoin Knots unified opt-in signature hash (SIGHASH_UNIFIED, 0x20).
 *
 * Spec: bitcoinknots/bitcoin doc/unified-sighash.md at v29.4.1.knots20260508
 * (Knots PR #357). Active on the BLAKE2b chain from the fork height
 * (961,640 mainnet, 150,308 testnet4). A transaction carrying at least one
 * opted-in signature is invalid on the SHA-256 chain, so it cannot be replayed.
 *
 * Verified against all 166 vectors in src/test/data/unified_sighash.json.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import type { Transaction } from '@scure/btc-signer';
import { tagSchnorr } from '@scure/btc-signer/utils.js';

export const SIGHASH_UNIFIED = 0x20;
export const SIGHASH_ALL_UNIFIED = 0x21;

const SIGHASH_NONE = 0x02;
const SIGHASH_SINGLE = 0x03;
const SIGHASH_ANYONECANPAY = 0x80;
const TAPSCRIPT_LEAF_VERSION = 0xc0;

export enum UnifiedScriptType {
  /** Bare script or P2SH, signed with ECDSA */
  Base = 0,
  /** Native or nested segwit v0, signed with ECDSA */
  WitnessV0 = 1,
  /** Taproot key path, signed with Schnorr */
  Taproot = 2,
  /** Taproot script path, signed with Schnorr */
  Tapscript = 3,
}

export type SpentOutput = { script: Uint8Array; amount: bigint };

/**
 * The fields of a transaction the sighash reads. txids are in display
 * (big-endian) order, as @scure/btc-signer stores them.
 */
export type UnifiedTx = {
  version: number;
  lockTime: number;
  inputs: { txid: Uint8Array; index: number; sequence: number }[];
  outputs: SpentOutput[];
};

/** Read a @scure/btc-signer Transaction into the shape unifiedSighash takes. */
export const fromScureTransaction = (tx: Transaction): UnifiedTx => ({
  version: tx.version,
  lockTime: tx.lockTime,
  inputs: Array.from({ length: tx.inputsLength }, (_, i) => {
    const input = tx.getInput(i);
    if (input.txid === undefined || input.index === undefined) {
      throw new Error(`input ${i} has no outpoint`);
    }
    return {
      txid: input.txid,
      index: input.index,
      sequence: input.sequence ?? 0xffffffff,
    };
  }),
  outputs: Array.from({ length: tx.outputsLength }, (_, i) => {
    const output = tx.getOutput(i);
    if (output.script === undefined || output.amount === undefined) {
      throw new Error(`output ${i} is incomplete`);
    }
    return { script: output.script, amount: output.amount };
  }),
});

export type UnifiedSighashOptions = {
  /** Required for Base and WitnessV0. For Tapscript, the leaf script. */
  scriptCode?: Uint8Array;
  /** Tapscript only */
  leafScript?: Uint8Array;
  /** Tapscript only, defaults to 0xc0 */
  leafVersion?: number;
  /** Tapscript only, defaults to none (0xffffffff) */
  codeSeparatorPos?: number;
  /** Taproot and Tapscript only */
  annex?: Uint8Array;
};

const u32 = (n: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
};

const i64 = (n: bigint): Uint8Array => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, BigInt.asIntN(64, n), true);
  return b;
};

const compactSize = (n: number): Uint8Array => {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, n >> 8]);
  if (n <= 0xffffffff) return concatBytes(new Uint8Array([0xfe]), u32(n));
  throw new Error('compact size too large');
};

const serString = (b: Uint8Array): Uint8Array =>
  concatBytes(compactSize(b.length), b);

// scure keeps txids in display (big-endian) order; the wire format is reversed.
const outpoint = (txid: Uint8Array, index: number): Uint8Array =>
  concatBytes(Uint8Array.from(txid).reverse(), u32(index));

const serOutput = (o: SpentOutput): Uint8Array =>
  concatBytes(i64(o.amount), serString(o.script));

export const unifiedSighash = (
  txOrScure: Transaction | UnifiedTx,
  inIdx: number,
  hashType: number,
  spentOutputs: SpentOutput[],
  scriptType: UnifiedScriptType,
  opts: UnifiedSighashOptions = {},
): Uint8Array => {
  const tx =
    'inputsLength' in txOrScure ? fromScureTransaction(txOrScure) : txOrScure;
  const { inputs, outputs } = tx;

  if (inIdx < 0 || inIdx >= inputs.length) {
    throw new Error('input index out of range');
  }
  if (spentOutputs.length !== inputs.length) {
    throw new Error('one spent output is required per input');
  }
  if (hashType < 0 || hashType > 0xff) {
    throw new Error('hash type must be one byte');
  }
  if ((hashType & SIGHASH_UNIFIED) === 0) {
    throw new Error('hash type does not opt in to SIGHASH_UNIFIED');
  }

  const outputType = hashType & 0x1f;
  const anyoneCanPay = (hashType & SIGHASH_ANYONECANPAY) !== 0;
  const taproot =
    scriptType === UnifiedScriptType.Taproot ||
    scriptType === UnifiedScriptType.Tapscript;

  if (taproot) {
    if ((hashType & ~(0x1f | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED)) !== 0) {
      throw new Error('undefined hash type for taproot');
    }
    if (![0x01, SIGHASH_NONE, SIGHASH_SINGLE].includes(outputType)) {
      throw new Error('undefined hash type for taproot');
    }
  }

  const parts: Uint8Array[] = [
    new Uint8Array([0x00]), // epoch
    new Uint8Array([hashType]),
    u32(tx.version),
    u32(tx.lockTime),
    new Uint8Array([0x00]), // locktime is 5 bytes; high byte reserved
  ];

  if (!anyoneCanPay) {
    parts.push(
      sha256(concatBytes(...inputs.map((i) => outpoint(i.txid, i.index)))),
      sha256(concatBytes(...spentOutputs.map((o) => i64(o.amount)))),
      sha256(concatBytes(...spentOutputs.map((o) => serString(o.script)))),
      sha256(concatBytes(...inputs.map((i) => u32(i.sequence)))),
    );
  }

  if (outputType !== SIGHASH_NONE && outputType !== SIGHASH_SINGLE) {
    parts.push(sha256(concatBytes(...outputs.map(serOutput))));
  }

  parts.push(new Uint8Array([scriptType]));

  if (anyoneCanPay) {
    const input = inputs[inIdx];
    parts.push(
      outpoint(input.txid, input.index),
      serOutput(spentOutputs[inIdx]),
      u32(input.sequence),
    );
  } else {
    parts.push(u32(inIdx));
  }

  if (!taproot) {
    if (opts.scriptCode === undefined) {
      throw new Error('scriptCode is required for base and segwit v0 inputs');
    }
    parts.push(serString(opts.scriptCode));
  } else {
    parts.push(new Uint8Array([opts.annex !== undefined ? 1 : 0]));
    if (opts.annex !== undefined) {
      parts.push(sha256(serString(opts.annex)));
    }
  }

  if (outputType === SIGHASH_SINGLE) {
    if (inIdx >= outputs.length) {
      throw new Error('SIGHASH_SINGLE without a matching output');
    }
    parts.push(sha256(serOutput(outputs[inIdx])));
  }

  if (scriptType === UnifiedScriptType.Tapscript) {
    const leaf = opts.leafScript ?? opts.scriptCode;
    if (leaf === undefined) {
      throw new Error('leafScript is required for tapscript inputs');
    }
    const leafVersion = opts.leafVersion ?? TAPSCRIPT_LEAF_VERSION;
    parts.push(
      tagSchnorr('TapLeaf', new Uint8Array([leafVersion]), serString(leaf)),
      new Uint8Array([0x00]), // key version
      u32(opts.codeSeparatorPos ?? 0xffffffff),
    );
  }

  return tagSchnorr('UnifiedSighash', concatBytes(...parts));
};
