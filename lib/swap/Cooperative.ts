import { SigHash, type Transaction } from '@scure/btc-signer';
import {
  SIGHASH_ALL_UNIFIED,
  type SpentOutput,
  UnifiedScriptType,
  unifiedSighash,
} from '../blake2b/UnifiedSighash.ts';
import type { SighashMode } from './Claim.ts';

/**
 * Message both parties sign with MuSig2 for a cooperative (key-path) Taproot
 * spend of input `index`. `spentOutputs` lists every input's prevout in the
 * transaction's input order.
 *
 * 'unified' hashes with SIGHASH_UNIFIED (0x21) so the spend is valid only on
 * the BLAKE2b chain. 'legacy' is BIP341 SIGHASH_DEFAULT, as upstream Boltz.
 */
export const cooperativeSighash = (
  tx: Transaction,
  index: number,
  spentOutputs: SpentOutput[],
  sighashMode: SighashMode = 'legacy',
): Uint8Array =>
  sighashMode === 'unified'
    ? unifiedSighash(
        tx,
        index,
        SIGHASH_ALL_UNIFIED,
        spentOutputs,
        UnifiedScriptType.Taproot,
      )
    : tx.preimageWitnessV1(
        index,
        spentOutputs.map((o) => o.script),
        SigHash.DEFAULT,
        spentOutputs.map((o) => o.amount),
      );

/**
 * Key-path witness from an aggregated 64-byte MuSig2 signature. Unified
 * signatures carry the 0x21 hash type byte, so they are 65 bytes.
 */
export const cooperativeWitness = (
  aggregatedSignature: Uint8Array,
  sighashMode: SighashMode = 'legacy',
): Uint8Array[] => {
  if (aggregatedSignature.length !== 64) {
    throw new Error('aggregated Schnorr signature must be 64 bytes');
  }
  if (sighashMode === 'legacy') return [aggregatedSignature];
  const sig = new Uint8Array(65);
  sig.set(aggregatedSignature);
  sig[64] = SIGHASH_ALL_UNIFIED;
  return [sig];
};
