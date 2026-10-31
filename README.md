# Shamir Mnemonic TypeScript

TypeScript implementation of [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) Shamir Secret Sharing for mnemonic seed phrases.

This is a complete conversion of the Python [python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic/tree/master) reference implementation to TypeScript for Node.js.

**Zero runtime dependencies.** This library does not depend on any third-party packages.

## Features

- **SLIP-0039 compliant**: binary-compatible with the standard mnemonic format
- **Group sharing**: split a secret across multiple groups (e.g. 2-of-3 groups, each with its own member threshold)
- **Passphrase protection**: optional encryption of the master secret (printable ASCII only)
- **Extendable backups**: shares created with the `extendable` flag (default) can later be extended with new shares for the same secret
- **Iteration exponent**: strengthens passphrase derivation (integer from 0 to 15, default 1)
- **Low-level API**: `splitEms` / `recoverEms` for working with encrypted master secrets, plus `encrypt` / `decrypt` and `decodeMnemonics`
- **Interactive recovery**: `RecoveryState` for step-by-step mnemonic entry and progress tracking
- **Stable error codes**: every error carries a `code` and metadata-only `details`, so apps can show their own messages

## Requirements

- **Node.js** >= 18.0.0

## Specification

See [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) for the full specification.

## Installation

```bash
npm install shamir-mnemonic-ts
```

## Usage

### Master secret

The master secret must have an **even length in bytes** (e.g. 16, 20, 24, 28, or 32). This is required because passphrase encryption uses a **Feistel cipher** that splits the secret into two equal halves (L and R); an odd length cannot be divided evenly.

- **Length**: at least 16 bytes (128 bits). In practice the master secret is a BIP32 master seed of 16 to 32 bytes, as in hardware wallets that support SLIP-0039.
- **Hex**: use a hex string with an **even number of characters** (2 hex digits = 1 byte). Example: `Buffer.from('b43ceb7e57a0ea8766221624d01b0864', 'hex')` (32 chars = 16 bytes).

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

As specified by SLIP-0039, a wrong passphrase does **not** raise an error: recovery silently returns a different secret. Check the recovered secret (for example against a known address) before relying on it.

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

// Add mnemonics one by one (e.g. from user input). Entering the same share twice
// is harmless; a share from another backup throws (NOT_IN_CURRENT_SET or CONFLICTING_SHARE).
state.addShare(shamir.Share.fromMnemonic(firstMnemonic));
state.addShare(shamir.Share.fromMnemonic(secondMnemonic));

state.groupStatus(0);   // [entered, threshold] for group 0
state.groupPrefix(0);   // first words of group 0
state.isComplete();     // true when enough shares to recover

const recovered = state.recover('my passphrase');
try {
  // use recovered
} finally {
  recovered.fill(0);
}
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

For React Native / Expo, browsers and other environments without Node `crypto`, use `./decode` to parse share mnemonics without loading `cipher` or `shamir`. It still needs a global `Buffer` (for example the [`buffer`](https://www.npmjs.com/package/buffer) package, assigned to `globalThis.Buffer` before the first import):

```typescript
import { Share, MnemonicError } from 'shamir-mnemonic-ts/decode';

const share = Share.fromMnemonic(mnemonic);
```

Exposes `Share`, `MnemonicError`, `ShamirError` and the types `ShareCommonParameters`, `ShareGroupParameters`, `ShamirErrorCode` and `ShamirErrorDetails` only. Split, combine, encryption, and recovery stay on the main entry point (`import * as shamir from 'shamir-mnemonic-ts'`).

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

`WORDLIST` is the official 1024-word list; each word is one `RADIX_BITS`-bit symbol. `WORD_INDEX` maps lowercase words to indices. Use this entry as the single source of truth when packing or validating share mnemonics outside the main API. Both are read-only: `WORDLIST` is frozen and `WORD_INDEX` throws on `set`, `delete` and `clear`. Like `./decode`, this entry needs a global `Buffer` outside Node.

## Errors

Every error thrown on purpose is a `ShamirError` with a stable `code` and a `details` object. Invalid mnemonics or sets of mnemonics throw `MnemonicError`, a subclass of `ShamirError`. Show your own (translated) messages from `code` and `details`; do not parse `message`, its wording may change.

```typescript
import * as shamir from 'shamir-mnemonic-ts';

try {
  shamir.combineMnemonics(mnemonics);
} catch (error) {
  if (error instanceof shamir.ShamirError && error.code === 'INVALID_WORD') {
    showError(t('invalidWord', { position: error.details.position }));
  }
}
```

`details` only holds metadata (positions, counts, field names), never share words or secret bytes. Codes are part of the public API: they only change in a major version.

Invalid mnemonics or sets of mnemonics (`MnemonicError`):

| Code | When | `details` |
|---|---|---|
| `INVALID_WORD` | A word is not in the SLIP-0039 wordlist | `position` (1-based; absent if the input is not a string) |
| `MNEMONIC_TOO_SHORT` | Fewer words than a share can have | `minWords` |
| `INVALID_MNEMONIC_LENGTH` | The word count does not match a valid share length | |
| `INVALID_CHECKSUM` | The checksum fails: typo, missing or swapped words | |
| `INVALID_PADDING` | Invalid padding bits in the share value | |
| `GROUP_THRESHOLD_EXCEEDS_GROUP_COUNT` | The share metadata is inconsistent | |
| `PARAMETERS_MISMATCH` | Shares of the same group disagree on a parameter | `field` |
| `MIXED_MNEMONIC_SETS` | Shares from different backups, or with different group settings | `wordCount` |
| `CONFLICTING_SHARE` | A share has the same index as another one but a different value | `index` |
| `DUPLICATE_SHARE_INDEX` | Two shares with the same index reach recovery | |
| `SHARE_LENGTH_MISMATCH` | Shares have different lengths | |
| `INVALID_DIGEST` | The recovered secret fails its integrity check: corrupted or mismatched shares | |
| `EMPTY_MNEMONICS` | No mnemonic was given | |
| `EMPTY_SHARES` | No share, or an empty group, was given | |
| `INSUFFICIENT_GROUPS` | Fewer groups than the group threshold | `required` |
| `WRONG_GROUP_COUNT` | More groups than the group threshold | `expected`, `provided` |
| `WRONG_MEMBER_COUNT` | A group does not have exactly its member threshold of shares | `expected`, `provided` |
| `NOT_IN_CURRENT_SET` | `RecoveryState`: the share belongs to another backup | |
| `INVALID_MNEMONIC` | Default code of a `MnemonicError` built without one | |

Invalid arguments or state (`ShamirError`):

| Code | When | `details` |
|---|---|---|
| `INVALID_THRESHOLD` | A threshold is not a positive integer | |
| `THRESHOLD_EXCEEDS_SHARE_COUNT` | A threshold is greater than the number of shares | |
| `INVALID_SHARE_COUNT` | A share count is not an integer | |
| `TOO_MANY_SHARES` | More than 16 shares or groups | `max` |
| `GROUP_THRESHOLD_EXCEEDS_GROUPS` | The group threshold is greater than the number of groups | |
| `MEMBER_THRESHOLD_ONE_NOT_ALLOWED` | Member threshold 1 with several shares (use 1-of-1) | |
| `MASTER_SECRET_TOO_SHORT` | The master secret is shorter than 16 bytes | `minBytes` |
| `MASTER_SECRET_ODD_LENGTH` | The master secret (or encrypted master secret) has an odd length | |
| `INVALID_MASTER_SECRET` | The master secret is not a `Buffer` | |
| `INVALID_ITERATION_EXPONENT` | The iteration exponent is not an integer from 0 to 15 | `max` |
| `INVALID_IDENTIFIER` | The identifier is not an integer from 0 to 32767 | `max` |
| `PASSPHRASE_NOT_PRINTABLE_ASCII` | At generation, the passphrase has characters outside printable ASCII | |
| `PASSPHRASE_NOT_UTF8` | A `Buffer` passphrase is not valid UTF-8 | |
| `INVALID_PASSPHRASE` | The passphrase is neither a string nor a `Buffer` | |
| `RECOVERY_NOT_STARTED` | `RecoveryState.groupPrefix` was called before any share was added | |

## Security

### Handling sensitive data

The following APIs return a `Buffer` containing the master secret:

- `combineMnemonics`
- `EncryptedMasterSecret.decrypt`
- `RecoveryState.recover`

**Callers must overwrite this buffer after use** (e.g. `buffer.fill(0)`) to limit exposure in memory. Do this in a `try/finally` block so cleanup runs even when an error is thrown. The usage examples in the [Usage](#usage) section are simplified; production code should apply this cleanup. See the [Secure cleanup](#secure-cleanup) example.

Error messages never include the secret part of a share. An unknown word is reported by its position (`Invalid mnemonic word at position 5.`), never echoed. Checksum, padding and grouping errors quote the first 3 or 4 words of a mnemonic: these words only encode metadata (identifier, thresholds, indices), not the secret, but they do tell which backup a share belongs to.

`Share`, `ShareGroup`, `EncryptedMasterSecret` and `RecoveryState` hide their secret bytes when passed to `JSON.stringify`, or to `console.log` and `util.inspect` in Node: only metadata is shown, and secret fields read `[redacted]`. This is a safety net against accidental logging, not a protection:

- reading a field directly (for example `share.value`) still gives the real data;
- `structuredClone`, Electron IPC and `postMessage`, object spread (`{ ...share }`), `Object.assign` and browser DevTools copy or show the real bytes.

Never send these objects over IPC or to another process: pass mnemonic strings and wipe them as soon as possible.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
