import * as shamir from '../src/index';
import { Share, MnemonicError } from '../src/decode';

const MS = Buffer.from('ABCDEFGHIJKLMNOP', 'utf8');

describe('decode entry point', () => {
  test('Share.fromMnemonic returns correct metadata from shares generated via full API', () => {
    const groupThreshold = 2;
    const memberThresholds = [3, 2];
    const groupSizes = [5, 3];
    const mnemonics = shamir.generateMnemonics(
      groupThreshold,
      memberThresholds.map((t, i) => [t, groupSizes[i]] as [number, number]),
      MS
    );

    const share0 = Share.fromMnemonic(mnemonics[0][0]);
    expect(share0.memberThreshold).toBe(3);
    expect(share0.groupCount).toBe(2);
    expect(share0.groupThreshold).toBe(2);
    expect(share0.groupIndex).toBe(0);
    expect(share0.index).toBe(0);

    const share1 = Share.fromMnemonic(mnemonics[1][2]);
    expect(share1.memberThreshold).toBe(2);
    expect(share1.groupCount).toBe(2);
    expect(share1.groupThreshold).toBe(2);
    expect(share1.groupIndex).toBe(1);
    expect(share1.index).toBe(2);
    expect(share1.identifier).toBe(share0.identifier);
  });

  test('invalid mnemonic throws MnemonicError', () => {
    expect(() => Share.fromMnemonic('invalid mnemonic words here')).toThrow(
      MnemonicError
    );
  });

  test('does not load cipher or shamir modules', () => {
    const mnemonic = shamir.generateMnemonics(1, [[3, 5]], MS)[0][0];

    jest.isolateModules(() => {
      const cacheBefore = new Set(Object.keys(require.cache));

      const { Share: IsolatedShare } = require('../src/decode') as typeof import('../src/decode');
      const share = IsolatedShare.fromMnemonic(mnemonic);
      expect(share.memberThreshold).toBe(3);

      const newlyLoaded = Object.keys(require.cache).filter((key) => !cacheBefore.has(key));
      expect(newlyLoaded.some((key) => /[\\/]cipher\.(js|ts)$/.test(key))).toBe(false);
      expect(newlyLoaded.some((key) => /[\\/]shamir\.(js|ts)$/.test(key))).toBe(false);
    });
  });
});
