/**
 * Runs against the built `dist/` (what is actually published), not `src/`.
 * Not part of `npm test`: run by `npm run test:dist`, after the build in `prepack`.
 */
import * as fs from 'fs';
import * as path from 'path';

const shamir = require('../dist/index');
const decode = require('../dist/decode');
const wordlist = require('../dist/wordlist');

type TestVector = [string, string[], string, string];

describe('Published dist', () => {
  const vectors: TestVector[] = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'vectors.json'), 'utf8')
  );

  test('passes every official SLIP-39 vector', () => {
    for (const [description, mnemonics, secretHex] of vectors) {
      if (secretHex) {
        const recovered: Buffer = shamir.combineMnemonics(mnemonics, 'TREZOR');
        expect({ description, hex: recovered.toString('hex') }).toEqual({ description, hex: secretHex });
      } else {
        expect(() => shamir.combineMnemonics(mnemonics)).toThrow(shamir.MnemonicError);
      }
    }
  });

  test('exposes the decode and wordlist entry points', () => {
    expect(typeof decode.Share.fromMnemonic).toBe('function');
    expect(decode.MnemonicError).toBe(shamir.MnemonicError);
    expect(decode.ShamirError).toBe(shamir.ShamirError);
    expect(wordlist.WORDLIST).toHaveLength(1024);
    expect(Object.isFrozen(wordlist.WORDLIST)).toBe(true);
  });

  test('errors carry stable codes', () => {
    expect.assertions(2);
    try {
      decode.Share.fromMnemonic('notaword');
    } catch (error) {
      expect((error as { code: string }).code).toBe('INVALID_WORD');
      expect((error as { details: unknown }).details).toEqual({ position: 1 });
    }
  });

  test('contains no stale build output', () => {
    const dist = path.join(__dirname, '..', 'dist');
    expect(fs.existsSync(path.join(dist, 'src'))).toBe(false);
    expect(fs.existsSync(path.join(dist, 'test-manual.js'))).toBe(false);
  });
});
