import { hex } from '@scure/base';
import { RawTx } from '@scure/btc-signer';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  UnifiedScriptType,
  unifiedSighash,
} from '../../../lib/blake2b/UnifiedSighash.ts';

// 166 vectors from bitcoinknots/bitcoin@v29.4.1.knots20260508
// src/test/data/unified_sighash.json. Row 0 is the header.
const rows = JSON.parse(
  readFileSync(join(__dirname, 'unified_sighash.json'), 'utf8'),
).slice(1) as [
  string,
  string,
  number,
  number,
  number,
  [number, string][],
  string,
][];

describe('unifiedSighash (Knots SIGHASH_UNIFIED)', () => {
  test.each(rows.map((r, i) => [i, ...r] as const))(
    'vector %i',
    (_i, scriptCode, rawTx, inIdx, hashType, scriptType, spent, expected) => {
      // RawTx, not Transaction.fromRaw: the vectors use arbitrary version numbers.
      const raw = RawTx.decode(hex.decode(rawTx));
      const tx = {
        version: raw.version,
        lockTime: raw.lockTime,
        inputs: raw.inputs.map((i) => ({
          txid: i.txid,
          index: i.index,
          sequence: i.sequence,
        })),
        outputs: raw.outputs.map((o) => ({
          amount: o.amount,
          script: o.script,
        })),
      };
      const spentOutputs = spent.map(([amount, script]) => ({
        amount: BigInt(amount),
        script: hex.decode(script),
      }));
      const code = hex.decode(scriptCode);
      const got = unifiedSighash(
        tx,
        inIdx,
        hashType,
        spentOutputs,
        scriptType as UnifiedScriptType,
        scriptType === UnifiedScriptType.Tapscript
          ? { leafScript: code }
          : { scriptCode: code },
      );
      expect(hex.encode(got)).toEqual(expected);
    },
  );
});
