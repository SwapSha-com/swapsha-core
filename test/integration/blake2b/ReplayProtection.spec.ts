/**
 * SwapSha replay-protection check (Blueprint D6, Phase 1 exit criterion).
 *
 * Needs the two-node regtest from swapsha_regtest.sh running:
 *   sha    127.0.0.1:18443  Knots 29.3, never schedules the fork
 *   blake  127.0.0.1:18543  Knots 29.4.1, BLAKE2b fork at height 200
 *
 * For each swap output type:
 *   1. Fund the HTLC on the SHA-256 chain from a PRE-FORK coin, signed the old
 *      way, and deliberately replay the same transaction onto BLAKE2b. The
 *      HTLC now exists on both chains with the same outpoint.
 *   2. Build the claim with sighashMode 'legacy'. Both chains accept it: the
 *      replay hazard SwapSha has to avoid.
 *   3. Build the claim with sighashMode 'unified' (0x21). BLAKE2b accepts it,
 *      SHA-256 rejects it with a script error: replay protected.
 *
 * Also covers refunds, MuSig2 cooperative claims, and BLAKE2b header hashing.
 *
 * Run: npm run test:replay
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '@scure/base';
import { Address, OutScript, Transaction } from '@scure/btc-signer';
import { hash160 } from '@scure/btc-signer/utils.js';
import { randomBytes } from 'node:crypto';
import { request } from 'node:http';
import {
  Musig,
  Networks,
  OutputType,
  type SighashMode,
  constructClaimTransaction,
  constructRefundTransaction,
  cooperativeSighash,
  cooperativeWitness,
  detectSwap,
} from '../../../lib/Boltz.ts';
import {
  blockHashHex,
  checkProofOfWork,
  parseBlockHeader,
} from '../../../lib/blake2b/BlockHeader.ts';
import type { ClaimDetails } from '../../../lib/consts/Types.ts';
import {
  outputFunctionForType,
  p2trOutput,
  p2wpkhOutput,
} from '../../../lib/swap/Scripts.ts';
import swapScript from '../../../lib/swap/SwapScript.ts';
import swapTree from '../../../lib/swap/SwapTree.ts';
import { tweakMusig } from '../../../lib/swap/TaprootUtils.ts';

const rpc =
  (port: number) =>
  <T>(method: string, params: unknown[] = []): Promise<T> =>
    new Promise((resolve, reject) => {
      const body = JSON.stringify({ jsonrpc: '1.0', id: 1, method, params });
      const req = request(
        {
          host: '127.0.0.1',
          port,
          path: '/wallet/prefork',
          method: 'POST',
          auth: 'swapsha:swapsha',
          headers: { 'content-type': 'application/json' },
        },
        (res) => {
          let buf = '';
          res.on('data', (c) => (buf += c));
          res.on('end', () => {
            try {
              const parsed = JSON.parse(buf);
              if (parsed.error) reject(parsed.error);
              else resolve(parsed.result);
            } catch {
              reject(new Error(`HTTP ${res.statusCode}: ${buf}`));
            }
          });
        },
      );
      req.on('error', reject);
      req.end(body);
    });

const sha = rpc(18443);
const blake = rpc(18543);

type MempoolResult = { allowed: boolean; 'reject-reason'?: string }[];

const FORK_HEIGHT = 200;
const PRE_FORK_MINCONF = 50;

const encodeAddress = (script: Uint8Array): string =>
  Address(Networks.regtest).encode(
    OutScript.decode(script) as Parameters<
      ReturnType<typeof Address>['encode']
    >[0],
  );

const destination = p2wpkhOutput(
  hash160(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey())),
);

/** Fund `script` from a pre-fork coin on SHA-256 and replay it onto BLAKE2b. */
const fundOnBothChains = async (
  script: Uint8Array,
  detectKey: Uint8Array,
): Promise<{
  transactionId: string;
  vout: number;
  amount: bigint;
  script: Uint8Array;
}> => {
  const address = encodeAddress(script);
  const { psbt } = await sha<{ psbt: string }>('walletcreatefundedpsbt', [
    [],
    [{ [address]: 0.001 }],
    0,
    { minconf: PRE_FORK_MINCONF, fee_rate: 10 },
  ]);
  const signed = await sha<{ psbt: string }>('walletprocesspsbt', [psbt]);
  const { hex: rawHex } = await sha<{ hex: string }>('finalizepsbt', [
    signed.psbt,
  ]);

  const transactionId = await sha<string>('sendrawtransaction', [rawHex]);
  // The replay: same bytes, other chain. Legacy signatures are valid on both.
  await blake<string>('sendrawtransaction', [rawHex]);

  const tx = Transaction.fromRaw(hex.decode(rawHex));
  const found = detectSwap(detectKey, tx);
  if (
    found === undefined ||
    found.amount === undefined ||
    found.script === undefined
  ) {
    throw new Error('swap output not found');
  }

  for (const node of [sha, blake]) {
    const to = await node<string>('getnewaddress');
    await node('generatetoaddress', [1, to]);
  }

  return {
    transactionId,
    vout: found.vout,
    amount: found.amount,
    script: found.script,
  };
};

type Built = {
  utxo: ClaimDetails;
  claimKey: Uint8Array;
  refundKey: Uint8Array;
};

const tipHeight = async () =>
  Math.max(
    await sha<number>('getblockcount'),
    await blake<number>('getblockcount'),
  );

/** Mine on whichever chain is behind until both are at least `height`. */
const mineBothTo = async (height: number) => {
  for (const node of [sha, blake]) {
    const have = await node<number>('getblockcount');
    if (have < height) {
      await node('generatetoaddress', [
        height - have,
        await node<string>('getnewaddress'),
      ]);
    }
  }
};

/**
 * Fund an HTLC of `outputType` on both chains. `refundable` sets the timeout
 * to the next block so the refund path is spendable right away.
 */
const buildUtxo = async (
  outputType: OutputType,
  refundable = false,
): Promise<Built> => {
  const claimKey = secp256k1.utils.randomSecretKey();
  const refundKey = secp256k1.utils.randomSecretKey();
  const preimage = randomBytes(32);
  const timeout = (await tipHeight()) + (refundable ? 1 : 100);

  let utxo: ClaimDetails;
  if (outputType === OutputType.Taproot) {
    const tree = swapTree(
      false,
      sha256(preimage),
      secp256k1.getPublicKey(claimKey),
      secp256k1.getPublicKey(refundKey),
      timeout,
    );
    const musig = Musig.create(
      claimKey,
      [claimKey, refundKey].map((k) => secp256k1.getPublicKey(k)),
    );
    const tweaked = tweakMusig(musig, tree.tree);
    const funded = await fundOnBothChains(
      p2trOutput(tweaked.aggPubkey),
      tweaked.aggPubkey,
    );
    utxo = {
      ...funded,
      type: outputType,
      preimage,
      privateKey: refundable ? refundKey : claimKey,
      swapTree: tree,
      internalKey: musig.aggPubkey,
    } as ClaimDetails;
  } else {
    const redeemScript = swapScript(
      sha256(preimage),
      secp256k1.getPublicKey(claimKey),
      secp256k1.getPublicKey(refundKey),
      timeout,
    );
    const funded = await fundOnBothChains(
      outputFunctionForType(outputType)!(redeemScript),
      redeemScript,
    );
    utxo = {
      ...funded,
      type: outputType,
      preimage,
      privateKey: refundable ? refundKey : claimKey,
      redeemScript,
    } as ClaimDetails;
  }

  if (refundable) await mineBothTo(timeout);
  return { utxo, claimKey, refundKey };
};

const accept = async (node: typeof sha, txHex: string) =>
  (await node<MempoolResult>('testmempoolaccept', [[txHex]]))[0];

const assertChainsSplit = async () => {
  const [shaHash, blakeHash] = await Promise.all([
    sha<string>('getblockhash', [FORK_HEIGHT]),
    blake<string>('getblockhash', [FORK_HEIGHT]),
  ]);
  if (shaHash === blakeHash) {
    throw new Error(
      `block ${FORK_HEIGHT} matches on both nodes: chains did not split`,
    );
  }
};

const expectReplayProtected = async (txHex: string) => {
  const onBlake = await accept(blake, txHex);
  const onSha = await accept(sha, txHex);
  expect(onBlake).toMatchObject({ allowed: true });
  expect(onSha.allowed).toBe(false);
  expect(onSha['reject-reason']).toMatch(/script-verify-flag-failed/);
};

const expectValidOnBoth = async (txHex: string) => {
  expect(await accept(blake, txHex)).toMatchObject({ allowed: true });
  expect(await accept(sha, txHex)).toMatchObject({ allowed: true });
};

const outputTypes = [
  ['P2WSH', OutputType.Bech32],
  ['P2SH-P2WSH', OutputType.Compatibility],
  ['P2SH', OutputType.Legacy],
  ['Taproot script', OutputType.Taproot],
] as const;

describe('BLAKE2b replay protection (SIGHASH_UNIFIED)', () => {
  beforeAll(assertChainsSplit);

  describe.each(outputTypes)('%s HTLC claim', (_name, outputType) => {
    let utxo: ClaimDetails;

    beforeAll(async () => {
      ({ utxo } = await buildUtxo(outputType));
    });

    test('legacy sighash is valid on BOTH chains (the replay hazard)', async () => {
      await expectValidOnBoth(
        constructClaimTransaction([utxo], destination, 2_000n).hex,
      );
    });

    test('unified sighash is valid on BLAKE2b and rejected on SHA-256', async () => {
      await expectReplayProtected(
        constructClaimTransaction(
          [utxo],
          destination,
          2_000n,
          true,
          undefined,
          false,
          'unified',
        ).hex,
      );
    });
  });

  describe.each(outputTypes)('%s HTLC refund', (_name, outputType) => {
    let utxo: ClaimDetails;
    let timeout: number;

    beforeAll(async () => {
      ({ utxo } = await buildUtxo(outputType, true));
      // nLockTime must not exceed either chain's height for the tx to be final
      timeout = Math.min(
        await sha<number>('getblockcount'),
        await blake<number>('getblockcount'),
      );
    });

    test('legacy refund is valid on BOTH chains', async () => {
      await expectValidOnBoth(
        constructRefundTransaction([utxo], destination, timeout, 2_000n).hex,
      );
    });

    test('unified refund is valid on BLAKE2b and rejected on SHA-256', async () => {
      await expectReplayProtected(
        constructRefundTransaction(
          [utxo],
          destination,
          timeout,
          2_000n,
          true,
          'unified',
        ).hex,
      );
    });
  });

  describe('Taproot cooperative (MuSig2 key path) claim', () => {
    let built: Built;

    beforeAll(async () => {
      built = await buildUtxo(OutputType.Taproot);
      built.utxo.cooperative = true;
    });

    const signCooperatively = (mode: SighashMode) => {
      const { utxo, claimKey, refundKey } = built;
      const tx = constructClaimTransaction(
        [utxo],
        destination,
        2_000n,
        true,
        undefined,
        false,
        mode,
      );
      const message = cooperativeSighash(
        tx,
        0,
        [{ script: utxo.script, amount: utxo.amount }],
        mode,
      );
      const publicKeys = [claimKey, refundKey].map((k) =>
        secp256k1.getPublicKey(k),
      );
      const tree = utxo.swapTree!.tree;
      const ours = tweakMusig(Musig.create(claimKey, publicKeys), tree)
        .message(message)
        .generateNonce();
      const theirs = tweakMusig(Musig.create(refundKey, publicKeys), tree)
        .message(message)
        .generateNonce();

      const oursSigned = ours
        .aggregateNonces([[publicKeys[1], theirs.publicNonce]])
        .initializeSession()
        .signPartial();
      const theirsSigned = theirs
        .aggregateNonces([[publicKeys[0], ours.publicNonce]])
        .initializeSession()
        .signPartial();

      const aggregated = oursSigned
        .addPartial(publicKeys[1], theirsSigned.ourPartialSignature)
        .aggregatePartials();

      tx.updateInput(0, {
        finalScriptWitness: cooperativeWitness(aggregated, mode),
      });
      return tx;
    };

    test('legacy key path is valid on BOTH chains', async () => {
      const tx = signCooperatively('legacy');
      expect(tx.getInput(0).finalScriptWitness![0]).toHaveLength(64);
      await expectValidOnBoth(tx.hex);
    });

    test('unified key path (65-byte signature) is valid on BLAKE2b and rejected on SHA-256', async () => {
      const tx = signCooperatively('unified');
      expect(tx.getInput(0).finalScriptWitness![0]).toHaveLength(65);
      await expectReplayProtected(tx.hex);
    });
  });

  describe('block headers', () => {
    const headersFrom = async (node: typeof sha, from: number, to: number) => {
      const out: { height: number; hash: string; raw: string }[] = [];
      for (let height = from; height <= to; height++) {
        const hash = await node<string>('getblockhash', [height]);
        out.push({
          height,
          hash,
          raw: await node<string>('getblockheader', [hash, false]),
        });
      }
      return out;
    };

    test('BLAKE2b chain: v1 before the fork, v2 from it, hashes match the node', async () => {
      const tip = await blake<number>('getblockcount');
      for (const { height, hash, raw } of await headersFrom(
        blake,
        FORK_HEIGHT - 3,
        Math.min(tip, FORK_HEIGHT + 20),
      )) {
        const header = parseBlockHeader(raw);
        expect(header.isV2).toBe(height >= FORK_HEIGHT);
        if (header.isV2) expect(header.height).toBe(height);
        expect(blockHashHex(header)).toBe(hash);
        expect(checkProofOfWork(header)).toBe(true);
      }
    });

    test('SHA-256 chain: v1 headers throughout, hashes match the node', async () => {
      const tip = await sha<number>('getblockcount');
      for (const { hash, raw } of await headersFrom(
        sha,
        FORK_HEIGHT - 3,
        Math.min(tip, FORK_HEIGHT + 20),
      )) {
        const header = parseBlockHeader(raw);
        expect(header.isV2).toBe(false);
        expect(blockHashHex(header)).toBe(hash);
      }
    });
  });
});
