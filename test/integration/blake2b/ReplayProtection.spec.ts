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
  constructClaimTransaction,
  detectSwap,
} from '../../../lib/Boltz.ts';
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

const buildUtxo = async (outputType: OutputType): Promise<ClaimDetails> => {
  const claimKey = secp256k1.utils.randomSecretKey();
  const refundKey = secp256k1.utils.randomSecretKey();
  const preimage = randomBytes(32);
  const timeout = (await sha<number>('getblockcount')) + 100;

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
    return {
      ...funded,
      type: outputType,
      preimage,
      privateKey: claimKey,
      swapTree: tree,
      internalKey: musig.aggPubkey,
    } as ClaimDetails;
  }

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
  return {
    ...funded,
    type: outputType,
    preimage,
    privateKey: claimKey,
    redeemScript,
  } as ClaimDetails;
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

describe('BLAKE2b replay protection (SIGHASH_UNIFIED)', () => {
  describe.each`
    name                | outputType
    ${'P2WSH'}          | ${OutputType.Bech32}
    ${'P2SH-P2WSH'}     | ${OutputType.Compatibility}
    ${'P2SH'}           | ${OutputType.Legacy}
    ${'Taproot script'} | ${OutputType.Taproot}
  `('$name HTLC claim', ({ outputType }) => {
    let utxo: ClaimDetails;

    beforeAll(async () => {
      await assertChainsSplit();
      utxo = await buildUtxo(outputType);
    });

    test('legacy sighash is valid on BOTH chains (the replay hazard)', async () => {
      const tx = constructClaimTransaction([utxo], destination, 2_000n);
      expect((await accept(blake, tx.hex)).allowed).toBe(true);
      expect((await accept(sha, tx.hex)).allowed).toBe(true);
    });

    test('unified sighash is valid on BLAKE2b and rejected on SHA-256', async () => {
      const tx = constructClaimTransaction(
        [utxo],
        destination,
        2_000n,
        true,
        undefined,
        false,
        'unified',
      );
      const onBlake = await accept(blake, tx.hex);
      const onSha = await accept(sha, tx.hex);

      expect(onBlake).toMatchObject({ allowed: true });
      expect(onSha.allowed).toBe(false);
      expect(onSha['reject-reason']).toMatch(/script-verify-flag-failed/);
    });
  });
});
