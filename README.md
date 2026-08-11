# Shamir Mnemonic TypeScript

TypeScript implementation of [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) Shamir Secret Sharing for mnemonic seed phrases.

This is a complete conversion of the Python [python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic/tree/master) reference implementation to TypeScript for Node.js.

**Zero runtime dependencies.** This library does not depend on any third-party packages.

## Features

- **SLIP-0039 compliant** — Binary-compatible with the standard mnemonic format
- **Group sharing** — Split a secret across multiple groups (e.g. 2-of-3 groups, each with its own member threshold)
- **Passphrase protection** — Optional encryption of the master secret (printable ASCII only)
- **Extendable backups** — Support for iteration exponent to strengthen passphrase derivation
- **Low-level API** — `splitEms` / `recoverEms` for working with encrypted master secrets, plus `encrypt` / `decrypt` and `decodeMnemonics`
- **Interactive recovery** — `RecoveryState` for step-by-step mnemonic entry and progress tracking

## Requirements

- **Node.js** >= 14.0.0

## Specification

See [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) for the full specification.

## Installation

```bash
npm install shamir-mnemonic-ts
```

## Usage

### Master secret

The master secret must have an **even length in bytes** (e.g. 16, 20, 24, 28, or 32). This is required because passphrase encryption uses a **Feistel cipher** that splits the secret into two equal halves (L and R); an odd length cannot be divided evenly.

- **Hex**: Use a hex string with an **even number of characters** (2 hex digits = 1 byte). Example: `Buffer.from('b43ceb7e57a0ea8766221624d01b0864', 'hex')` (32 chars = 16 bytes).
- **BIP39**: BIP39 seed (128–256 bits) always has an even byte length (16, 20, 24, 28, 32), so it is suitable as a master secret.

### Basic: split and recover

```typescript
import * as shamir from 'shamir-mnemonic-ts';

const masterSecret = Buffer.from('b43ceb7e57a0ea8766221624d01b0864', 'hex');
const mnemonics = shamir.generateMnemonics(
  1,           // group threshold (1 group required)
  [[3, 5]],    // (member threshold, member count): 3 of 5 shares per group
  masterSecret
);

// Recover with any 3 of 5 shares
const recovered = shamir.combineMnemonics(mnemonics[0].slice(0, 3));
```

Production code should wipe the recovered buffer after use; see [Handling sensitive data](#handling-sensitive-data) and the [Secure cleanup](#secure-cleanup) example.

### With passphrase

```typescript
import * as shamir from 'shamir-mnemonic-ts';

const masterSecret = Buffer.from('b43ceb7e57a0ea8766221624d01b0864', 'hex');
const mnemonics = shamir.generateMnemonics(
  1,
  [[3, 5]],
  masterSecret,
  'my passphrase'
)[0];

const recovered = shamir.combineMnemonics(
  mnemonics.slice(0, 3),
  'my passphrase'
);
```

You can also pass a UTF-8-encoded `Buffer` instead of a string; the passphrase must contain only printable ASCII characters (code points 32–126).

### Group sharing (e.g. 2-of-3 groups)

```typescript
import * as shamir from 'shamir-mnemonic-ts';

const masterSecret = Buffer.from('b43ceb7e57a0ea8766221624d01b0864', 'hex');
// 2 groups required; each group has (member threshold, member count)
const mnemonics = shamir.generateMnemonics(
  2,                      // group threshold
  [[3, 5], [2, 3], [1, 1]],  // group 0: 3-of-5, group 1: 2-of-3, group 2: 1-of-1
  masterSecret
);

// Recover with any 2 groups (e.g. 3 from group 0 + 2 from group 1)
const subset = [
  ...mnemonics[0].slice(0, 3),
  ...mnemonics[1].slice(0, 2),
];
const recovered = shamir.combineMnemonics(subset);
```

### Interactive recovery with `RecoveryState`

```typescript
import * as shamir from 'shamir-mnemonic-ts';

const state = new shamir.RecoveryState();

// Add mnemonics one by one (e.g. from user input)
function addMnemonic(mnemonic: string) {
  const groups = shamir.decodeMnemonics([mnemonic]);
  for (const group of groups.values()) {
    for (const share of group) state.addShare(share);
  }
}
addMnemonic('academic academic academic ...');  // first share
addMnemonic('academic academic academic ...');  // second share
// ...

state.groupStatus(0);   // [entered, threshold] for group 0
state.groupPrefix(0);   // first words of group 0
state.isComplete();     // true when enough shares to recover

const recovered = state.recover('my passphrase');
```

### Secure cleanup

Always wipe the recovered master secret after use. Use `try/finally` so cleanup runs even on error:

```typescript
import * as shamir from 'shamir-mnemonic-ts';

const mnemonics = [/* ... */];
let recovered: Buffer | null = null;
try {
  recovered = shamir.combineMnemonics(mnemonics);
  // use recovered (e.g. derive keys, compare, pass to another module)
} finally {
  if (recovered) recovered.fill(0);
}
```

### Entry point: `shamir-mnemonic-ts/decode`

For React Native / Expo and other environments without Node `crypto`, use `./decode` to parse share mnemonics without loading `cipher` or `shamir`:

```typescript
import { Share, MnemonicError } from 'shamir-mnemonic-ts/decode';

const share = Share.fromMnemonic(mnemonic);
```

Exposes `Share`, `ShareCommonParameters`, `ShareGroupParameters`, and `MnemonicError` only. Split, combine, encryption, and recovery stay on the main entry point (`import * as shamir from 'shamir-mnemonic-ts'`).

### Entry point: `shamir-mnemonic-ts/wordlist`

The SLIP-0039 wordlist and word↔index helpers, without loading split/combine or cipher:

```typescript
import {
  WORDLIST,
  WORD_INDEX,
  RADIX_BITS,
  mnemonicToIndices,
  mnemonicFromIndices,
  wordsFromIndices,
} from 'shamir-mnemonic-ts/wordlist';
```

`WORDLIST` is the official 1024-word list; each word is one `RADIX_BITS`-bit symbol. `WORD_INDEX` maps lowercase words to indices. Use this entry as the single source of truth when packing or validating share mnemonics outside the main API.

## Security

### Handling sensitive data

The following APIs return a `Buffer` containing the master secret:

- `combineMnemonics`
- `EncryptedMasterSecret.decrypt`
- `RecoveryState.recover`

**Callers must overwrite this buffer after use** (e.g. `buffer.fill(0)`) to limit exposure in memory. Do this in a `try/finally` block so cleanup runs even when an error is thrown. The usage examples in the [Usage](#usage) section are simplified; production code should apply this cleanup. See the [Secure cleanup](#secure-cleanup) example.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
