import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { Script, SigHash, Transaction } from '@scure/btc-signer';
import { signECDSA, signSchnorr } from '@scure/btc-signer/utils.js';
import { OutputType } from '../Boltz.ts';
import {
  SIGHASH_ALL_UNIFIED,
  UnifiedScriptType,
  unifiedSighash,
} from '../blake2b/UnifiedSighash.ts';
import { Errors } from '../consts/Errors.ts';
import {
  type ClaimDetails,
  type FundingAddressTree,
  type SwapTree,
  isSwapTree,
} from '../consts/Types.ts';
import { compareInputs } from './Bip69.ts';
import { createControlBlock, taprootHashTree } from './TaprootUtils.ts';

const LEGACY_SIGHASH = SigHash.ALL;
const DUMMY_TAPROOT_SIGNATURE = new Uint8Array(64);

/**
 * 'legacy': the signature hashes Bitcoin has always used. Valid on both chains.
 * 'unified': Knots SIGHASH_UNIFIED (0x21). Valid only on the BLAKE2b chain, so
 * the transaction cannot be replayed onto the SHA-256 chain. SwapSha uses this
 * for every BLAKE2b-side spend (D6).
 */
export type SighashMode = 'legacy' | 'unified';

export const isRelevantTaprootOutput = (
  utxo: Pick<ClaimDetails, 'type' | 'cooperative'>,
): boolean => utxo.type === OutputType.Taproot && utxo.cooperative !== true;

export const validateInputs = (
  utxos: Pick<
    ClaimDetails,
    'type' | 'redeemScript' | 'swapTree' | 'internalKey'
  >[],
): void => {
  if (
    utxos
      .filter((utxo) => utxo.type !== OutputType.Taproot)
      .some((utxo) => utxo.redeemScript === undefined)
  ) {
    throw new Error('not all non Taproot inputs have a redeem script');
  }

  const relevantTaprootOutputs = utxos.filter(isRelevantTaprootOutput);

  if (relevantTaprootOutputs.some((utxo) => utxo.swapTree === undefined)) {
    throw new Error('not all Taproot inputs have a swap tree');
  }

  if (relevantTaprootOutputs.some((utxo) => utxo.internalKey === undefined)) {
    throw new Error('not all Taproot inputs have an internal key');
  }
};

export const getClaimLeaf = (
  swapTree: SwapTree | FundingAddressTree,
): SwapTree['claimLeaf'] => {
  if (!isSwapTree(swapTree)) {
    throw new Error(Errors.claimRequiresClaimLeaf);
  }

  return swapTree.claimLeaf;
};

export const getTapLeaf = (
  isRefund: boolean,
  swapTree: SwapTree | FundingAddressTree,
): SwapTree['refundLeaf'] =>
  isRefund ? swapTree.refundLeaf : getClaimLeaf(swapTree);

export const constructClaimTransaction = (
  utxos: ClaimDetails[],
  destinationScript: Uint8Array,
  fee: bigint,
  isRbf = true,
  timeoutBlockHeight?: number,
  isRefund = false,
  sighashMode: SighashMode = 'legacy',
): Transaction => {
  const unified = sighashMode === 'unified';
  validateInputs(utxos);

  // BIP69 lexicographical input ordering
  const sortedUtxos = [...utxos].sort(compareInputs);

  const tx = new Transaction({
    version: 2,
    lockTime: timeoutBlockHeight,
  });

  const inputSum = sortedUtxos.reduce(
    (acc, utxo) => acc + utxo.amount,
    BigInt(0),
  );

  tx.addOutput({
    amount: inputSum - fee,
    script: destinationScript,
  });

  for (const utxo of sortedUtxos) {
    tx.addInput({
      txid: utxo.transactionId,
      index: utxo.vout,
      sequence: isRbf ? 0xfffffffd : 0xffffffff,
    });
  }

  const spentOutputs = sortedUtxos.map((out) => ({
    script: out.script,
    amount: out.amount,
  }));

  for (const [index, utxo] of sortedUtxos.entries()) {
    switch (utxo.type) {
      case OutputType.Legacy: {
        const hash = unified
          ? unifiedSighash(
              tx,
              index,
              SIGHASH_ALL_UNIFIED,
              spentOutputs,
              UnifiedScriptType.Base,
              { scriptCode: utxo.redeemScript },
            )
          : // biome-ignore lint/complexity/useLiteralKeys: only way to get the hash to sign for the legacy input
            tx['preimageLegacy'](index, utxo.redeemScript, LEGACY_SIGHASH);
        tx.updateInput(index, {
          finalScriptSig: Script.encode([
            signLegacy(hash, utxo.privateKey, unified),
            utxo.preimage,
            utxo.redeemScript,
          ]),
        });
        break;
      }
      case OutputType.Compatibility: {
        tx.updateInput(index, {
          finalScriptSig: Script.encode([
            Script.encode(['OP_0', sha256(utxo.redeemScript)]),
          ]),
        });
        break;
      }
    }

    // Construct and sign the witness for (nested) SegWit inputs
    // When the Taproot output is spent cooperatively, we leave it empty
    if (utxo.type === OutputType.Taproot) {
      if (utxo.cooperative === true) {
        tx.updateInput(index, {
          finalScriptWitness: [DUMMY_TAPROOT_SIGNATURE],
        });

        continue;
      }

      if (utxo.swapTree === undefined || utxo.internalKey === undefined) {
        throw new Error('swap tree or internal key is undefined');
      }

      const tapLeaf = getTapLeaf(isRefund, utxo.swapTree);

      const sigHash = unified
        ? unifiedSighash(
            tx,
            index,
            SIGHASH_ALL_UNIFIED,
            spentOutputs,
            UnifiedScriptType.Tapscript,
            { leafScript: tapLeaf.output, leafVersion: tapLeaf.version },
          )
        : tx.preimageWitnessV1(
            index,
            sortedUtxos.map((out) => out.script),
            SigHash.DEFAULT,
            sortedUtxos.map((out) => out.amount),
            undefined,
            tapLeaf.output,
            tapLeaf.version,
          );
      // SIGHASH_DEFAULT cannot carry the opt-in, so unified taproot
      // signatures are always 65 bytes: the Schnorr signature plus 0x21.
      const signature = unified
        ? concatBytes(
            signSchnorr(sigHash, utxo.privateKey),
            new Uint8Array([SIGHASH_ALL_UNIFIED]),
          )
        : signSchnorr(sigHash, utxo.privateKey);
      const witness: Uint8Array[] = [signature];

      if (!isRefund) {
        witness.push(utxo.preimage);
      }

      witness.push(tapLeaf.output);
      witness.push(
        createControlBlock(
          taprootHashTree(utxo.swapTree.tree),
          tapLeaf,
          utxo.internalKey,
        ),
      );

      tx.updateInput(index, {
        finalScriptWitness: witness,
      });
    } else if (
      utxo.type === OutputType.Bech32 ||
      utxo.type === OutputType.Compatibility
    ) {
      const sigHash = unified
        ? unifiedSighash(
            tx,
            index,
            SIGHASH_ALL_UNIFIED,
            spentOutputs,
            UnifiedScriptType.WitnessV0,
            { scriptCode: utxo.redeemScript },
          )
        : tx.preimageWitnessV0(
            index,
            utxo.redeemScript,
            LEGACY_SIGHASH,
            utxo.amount,
          );
      tx.updateInput(index, {
        finalScriptWitness: [
          signLegacy(sigHash, utxo.privateKey, unified),
          utxo.preimage,
          utxo.redeemScript,
        ],
      });
    }
  }

  return tx;
};

export const signLegacy = (
  hash: Uint8Array,
  privateKey: Uint8Array,
  unified = false,
): Uint8Array => {
  return concatBytes(
    signECDSA(hash, privateKey, true),
    new Uint8Array([unified ? SIGHASH_ALL_UNIFIED : LEGACY_SIGHASH]),
  );
};
