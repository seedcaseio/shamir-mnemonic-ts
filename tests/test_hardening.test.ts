import * as shamir from '../src/index';

const MS = Buffer.from('ABCDEFGHIJKLMNOP', 'utf8');

describe('Error messages never echo user input', () => {
  const share = shamir.generateMnemonics(1, [[1, 1]], MS)[0][0];
  const words = share.split(' ');

  test('a share pasted with commas does not leak into the error', () => {
    expect.assertions(3);
    try {
      shamir.Share.fromMnemonic(words.join(','));
    } catch (error) {
      const message = (error as Error).message;
      expect(error).toBeInstanceOf(shamir.MnemonicError);
      expect(message).toBe('Invalid mnemonic word at position 1.');
      // Compare whole words: "valid" is a SLIP-39 word and a substring of "Invalid".
      const messageWords = new Set(message.toLowerCase().split(/[^a-z]+/));
      expect(words.some((w) => messageWords.has(w))).toBe(false);
    }
  });

  test('the error gives the position of the invalid word', () => {
    const typo = [...words];
    typo[4] = 'notaword';
    expect(() => shamir.Share.fromMnemonic(typo.join(' '))).toThrow(
      'Invalid mnemonic word at position 5.'
    );
  });
});

describe('Input tolerance', () => {
  const mnemonics = shamir.generateMnemonics(1, [[2, 3]], MS)[0];

  test('leading and trailing whitespace is ignored', () => {
    const padded = mnemonics.slice(0, 2).map((m) => `  ${m}\n`);
    expect(shamir.combineMnemonics(padded).equals(MS)).toBe(true);
  });

  test('combineMnemonics accepts any iterable, including a generator', () => {
    function* gen() {
      yield mnemonics[0];
      yield mnemonics[1];
    }
    expect(shamir.combineMnemonics(gen()).equals(MS)).toBe(true);
  });

  test('an empty iterable is still rejected', () => {
    expect(() => shamir.combineMnemonics([])).toThrow('The list of mnemonics is empty.');
  });
});

describe('Duplicate shares count once', () => {
  const [a, b] = shamir.generateMnemonics(1, [[2, 3]], MS)[0];

  test('combineMnemonics recovers with a repeated share', () => {
    expect(shamir.combineMnemonics([a, a, b]).equals(MS)).toBe(true);
  });

  test('a repeated share does not complete a RecoveryState', () => {
    const state = new shamir.RecoveryState();
    const shareA = shamir.Share.fromMnemonic(a);
    state.addShare(shareA);
    state.addShare(shamir.Share.fromMnemonic(a));
    expect(state.isComplete()).toBe(false);
    state.addShare(shamir.Share.fromMnemonic(b));
    expect(state.isComplete()).toBe(true);
    expect(state.recover('').equals(MS)).toBe(true);
  });
});

describe('Generation parameters are validated', () => {
  test.each([
    ['non-integer member threshold', 1, [[1.5, 3]]],
    ['non-integer member count', 1, [[2, 3.5]]],
    ['NaN member count', 1, [[2, NaN]]],
    ['NaN group threshold', NaN, [[2, 3]]],
    ['non-integer group threshold', 1.5, [[2, 3], [2, 3]]],
  ] as Array<[string, number, Array<[number, number]>]>)('%s is rejected', (_name, gt, groups) => {
    expect(() => shamir.generateMnemonics(gt, groups, MS)).toThrow(/must be a positive integer/);
  });

  test.each([-1, 16, 32, 1.5, NaN])('iteration exponent %p is rejected', (e) => {
    expect(() => shamir.generateMnemonics(1, [[2, 3]], MS, '', true, e)).toThrow(
      'The iteration exponent must be an integer between 0 and 15.'
    );
  });

  // 15 is valid too but means ~330M PBKDF2 iterations, too slow for a unit test.
  test('valid iteration exponents are accepted', () => {
    for (const e of [0, 2]) {
      const mnemonics = shamir.generateMnemonics(1, [[1, 1]], MS, '', true, e)[0];
      expect(shamir.combineMnemonics(mnemonics).equals(MS)).toBe(true);
    }
  });

  test('a master secret that is not a Buffer is rejected', () => {
    expect(() =>
      shamir.generateMnemonics(1, [[2, 3]], 'ABCDEFGHIJKLMNOP' as unknown as Buffer)
    ).toThrow('The master secret must be a Buffer.');
  });

  test('splitEms rejects out-of-range EMS parameters', () => {
    const ems = new shamir.EncryptedMasterSecret(1 << 15, true, 1, Buffer.alloc(16));
    expect(() => shamir.splitEms(1, [[2, 3]], ems)).toThrow(
      'The identifier must be an integer between 0 and 32767.'
    );
  });
});

function errorOf(fn: () => unknown): shamir.ShamirError {
  try {
    fn();
  } catch (error) {
    return error as shamir.ShamirError;
  }
  throw new Error('Expected an error');
}

describe('Errors carry stable codes', () => {
  // Fixed identifiers: random ones could collide (1 in 32768) and change the error.
  const emsA = shamir.EncryptedMasterSecret.fromMasterSecret(MS, Buffer.alloc(0), 1, true, 0);
  const emsB = shamir.EncryptedMasterSecret.fromMasterSecret(MS, Buffer.alloc(0), 2, true, 0);
  const toMnemonics = (groups: shamir.Share[][]) => groups.map((g) => g.map((s) => s.mnemonic()));
  const [a1, a2] = toMnemonics(shamir.splitEms(1, [[2, 3]], emsA))[0];
  const [b1] = toMnemonics(shamir.splitEms(1, [[2, 3]], emsB))[0];
  const twoGroups = toMnemonics(shamir.splitEms(2, [[1, 1], [1, 1]], emsA));
  const otherTwoGroups = toMnemonics(shamir.splitEms(2, [[1, 1], [1, 1]], emsB));
  const oneOfTwoGroups = toMnemonics(shamir.splitEms(1, [[1, 1], [1, 1]], emsA));

  test.each([
    ['INVALID_WORD', () => shamir.Share.fromMnemonic(`${a1} notaword`), { position: 21 }],
    ['MNEMONIC_TOO_SHORT', () => shamir.Share.fromMnemonic('academic acid'), { minWords: 20 }],
    ['EMPTY_MNEMONICS', () => shamir.combineMnemonics([]), {}],
    ['PARAMETERS_MISMATCH', () => shamir.combineMnemonics([a1, b1]), { field: 'identifier' }],
    [
      'MIXED_MNEMONIC_SETS',
      () => shamir.combineMnemonics([twoGroups[0][0], otherTwoGroups[1][0]]),
      { wordCount: 2 },
    ],
    ['WRONG_MEMBER_COUNT', () => shamir.combineMnemonics([a1]), { expected: 2, provided: 1 }],
    ['INSUFFICIENT_GROUPS', () => shamir.combineMnemonics(twoGroups[0]), { required: 2 }],
    [
      'WRONG_GROUP_COUNT',
      () => shamir.combineMnemonics([oneOfTwoGroups[0][0], oneOfTwoGroups[1][0]]),
      { expected: 1, provided: 2 },
    ],
  ] as Array<[string, () => unknown, object]>)('%s (MnemonicError)', (code, fn, details) => {
    const error = errorOf(fn);
    expect(error).toBeInstanceOf(shamir.MnemonicError);
    expect(error).toBeInstanceOf(shamir.ShamirError);
    expect(error.code).toBe(code);
    expect(error.details).toEqual(details);
  });

  test('INVALID_CHECKSUM (MnemonicError)', () => {
    const words = a1.split(' ');
    words[10] = words[10] === 'academic' ? 'acid' : 'academic';
    expect(errorOf(() => shamir.Share.fromMnemonic(words.join(' '))).code).toBe('INVALID_CHECKSUM');
  });

  test.each([
    ['INVALID_THRESHOLD', () => shamir.generateMnemonics(1, [[0, 3]], MS)],
    ['THRESHOLD_EXCEEDS_SHARE_COUNT', () => shamir.generateMnemonics(1, [[3, 2]], MS)],
    ['TOO_MANY_SHARES', () => shamir.generateMnemonics(1, [[2, 17]], MS)],
    ['GROUP_THRESHOLD_EXCEEDS_GROUPS', () => shamir.generateMnemonics(2, [[2, 3]], MS)],
    ['MEMBER_THRESHOLD_ONE_NOT_ALLOWED', () => shamir.generateMnemonics(1, [[1, 3]], MS)],
    ['MASTER_SECRET_TOO_SHORT', () => shamir.generateMnemonics(1, [[2, 3]], Buffer.alloc(8))],
    ['MASTER_SECRET_ODD_LENGTH', () => shamir.generateMnemonics(1, [[2, 3]], Buffer.alloc(17))],
    ['INVALID_MASTER_SECRET', () => shamir.generateMnemonics(1, [[2, 3]], 'x' as unknown as Buffer)],
    ['INVALID_ITERATION_EXPONENT', () => shamir.generateMnemonics(1, [[2, 3]], MS, '', true, 16)],
    ['PASSPHRASE_NOT_PRINTABLE_ASCII', () => shamir.generateMnemonics(1, [[2, 3]], MS, 'café')],
    ['PASSPHRASE_NOT_UTF8', () => shamir.combineMnemonics([a1, a2], Buffer.from([0xff]))],
    ['INVALID_PASSPHRASE', () => shamir.combineMnemonics([a1, a2], new Uint8Array(1) as unknown as Buffer)],
    ['INVALID_SHARE_COUNT', () => shamir.generateMnemonics(1, [[2, 2.5]], MS)],
    ['RECOVERY_NOT_STARTED', () => new shamir.RecoveryState().groupPrefix(0)],
  ] as Array<[string, () => unknown]>)('%s (ShamirError, not MnemonicError)', (code, fn) => {
    const error = errorOf(fn);
    expect(error).toBeInstanceOf(shamir.ShamirError);
    expect(error).not.toBeInstanceOf(shamir.MnemonicError);
    expect(error.code).toBe(code);
  });

  test('NOT_IN_CURRENT_SET', () => {
    const state = new shamir.RecoveryState();
    state.addShare(shamir.Share.fromMnemonic(a1));
    expect(errorOf(() => state.addShare(shamir.Share.fromMnemonic(b1))).code).toBe('NOT_IN_CURRENT_SET');
  });

  test('EMPTY_SHARES for a group without shares', () => {
    const groups = new Map([[0, new shamir.ShareGroup()]]);
    expect(errorOf(() => shamir.recoverEms(groups)).code).toBe('EMPTY_SHARES');
  });

  test('details are frozen', () => {
    const error = errorOf(() => shamir.Share.fromMnemonic('notaword'));
    expect(Object.isFrozen(error.details)).toBe(true);
  });
});

describe('Conflicting shares are rejected', () => {
  // Two splits of the same extendable EMS: same identifier and indices, different values.
  const ems = shamir.EncryptedMasterSecret.fromMasterSecret(MS, Buffer.alloc(0), 42, true, 0);
  const [first] = shamir.splitEms(1, [[2, 3]], ems);
  const [second] = shamir.splitEms(1, [[2, 3]], ems);

  test('combineMnemonics fails early with CONFLICTING_SHARE', () => {
    const error = errorOf(() =>
      shamir.combineMnemonics([first[0].mnemonic(), second[0].mnemonic(), first[1].mnemonic()])
    );
    expect(error.code).toBe('CONFLICTING_SHARE');
    expect(error.details).toEqual({ index: 0 });
  });

  test('a RecoveryState refuses the conflicting share and can still complete', () => {
    const state = new shamir.RecoveryState();
    state.addShare(first[0]);
    expect(errorOf(() => state.addShare(second[0])).code).toBe('CONFLICTING_SHARE');
    state.addShare(first[1]);
    expect(state.recover('').equals(MS)).toBe(true);
  });
});

describe('Secret bytes never appear in JSON or console output', () => {
  const ems = shamir.EncryptedMasterSecret.fromMasterSecret(MS, Buffer.alloc(0), 42, true, 0);
  const [shares] = shamir.splitEms(1, [[2, 3]], ems);
  const group = new shamir.ShareGroup();
  group.add(shares[0]);
  const state = new shamir.RecoveryState();
  state.addShare(shares[0]);
  const { inspect } = require('util');

  const secrets = [ems.ciphertext, shares[0].value].map((b) => b.toString('hex'));
  const asBytes = (b: Buffer) => JSON.stringify(Array.from(b));

  test.each([
    ['Share', shares[0]],
    ['ShareGroup', group],
    ['EncryptedMasterSecret', ems],
    ['RecoveryState', state],
  ] as Array<[string, object]>)('%s', (_name, obj) => {
    for (const output of [JSON.stringify(obj), inspect(obj, { depth: 10 })]) {
      for (const hex of secrets) expect(output).not.toContain(hex);
      expect(output).not.toContain(asBytes(shares[0].value).slice(1, -1));
      expect(output).not.toContain(asBytes(ems.ciphertext).slice(1, -1));
    }
  });

  test('metadata stays visible', () => {
    expect(JSON.parse(JSON.stringify(shares[0]))).toMatchObject({ identifier: 42, index: 0, value: '[redacted]' });
  });
});

describe('Word list cannot be modified', () => {
  const wordlist = require('../src/wordlist');

  test('WORDLIST is frozen', () => {
    expect(Object.isFrozen(wordlist.WORDLIST)).toBe(true);
    expect(() => (wordlist.WORDLIST as string[]).reverse()).toThrow(TypeError);
  });

  test('WORD_INDEX refuses changes', () => {
    expect(() => wordlist.WORD_INDEX.set('zzz', 0)).toThrow('WORD_INDEX is read-only.');
    expect(() => wordlist.WORD_INDEX.delete('academic')).toThrow('WORD_INDEX is read-only.');
    expect(() => wordlist.WORD_INDEX.clear()).toThrow('WORD_INDEX is read-only.');
    expect(wordlist.WORD_INDEX.get('academic')).toBe(0);
    expect(wordlist.WORD_INDEX.size).toBe(1024);
  });
});

describe('Low-level cipher validates its parameters', () => {
  test.each([-1, 16, 20, 1.5])('encrypt and decrypt reject iteration exponent %p', (e) => {
    expect(errorOf(() => shamir.encrypt(MS, Buffer.alloc(0), e, 1, true)).code).toBe('INVALID_ITERATION_EXPONENT');
    expect(errorOf(() => shamir.decrypt(MS, Buffer.alloc(0), e, 1, true)).code).toBe('INVALID_ITERATION_EXPONENT');
  });

  test('encrypt and decrypt reject an out-of-range identifier', () => {
    expect(errorOf(() => shamir.encrypt(MS, Buffer.alloc(0), 0, 1 << 15, false)).code).toBe('INVALID_IDENTIFIER');
    expect(errorOf(() => shamir.decrypt(MS, Buffer.alloc(0), 0, -1, false)).code).toBe('INVALID_IDENTIFIER');
  });

  test('a member count of 0 keeps its previous message', () => {
    const error = errorOf(() => shamir.generateMnemonics(1, [[2, 0]], MS));
    expect(error.code).toBe('THRESHOLD_EXCEEDS_SHARE_COUNT');
    expect(error.message).toBe('The requested threshold must not exceed the number of shares.');
  });

  test('encrypt and decrypt still round-trip', () => {
    const passphrase = Buffer.from('TREZOR');
    const ciphertext = shamir.encrypt(MS, passphrase, 0, 7, false);
    expect(shamir.decrypt(ciphertext, passphrase, 0, 7, false).equals(MS)).toBe(true);
  });
});
