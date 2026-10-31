# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

## 1.3.0 - 2026-10-31

Share format, wordlist and SLIP-0039 compatibility are unchanged: shares created with earlier versions recover the same way.

### Added

- JSDoc of the public functions and methods now appears in the type declarations (it was placed inside function bodies).
- `ShamirError`, base class of every error thrown on purpose, with a stable `code` (`ShamirErrorCode`) and a frozen, metadata-only `details` object. `MnemonicError` now extends it. See the error table in the README.
- `ShamirError`, `ShamirErrorCode` and `ShamirErrorDetails` are also exported from `shamir-mnemonic-ts/decode`.
- `Share`, `ShareGroup`, `EncryptedMasterSecret` and `RecoveryState` hide their secret bytes from `JSON.stringify`, `console.log` and `util.inspect` (`[redacted]`).
- `typesVersions`, so the types of `shamir-mnemonic-ts/decode` and `shamir-mnemonic-ts/wordlist` resolve with TypeScript's `node` module resolution.

### Changed

- The invalid word error reports the position of the word instead of echoing it: `Invalid mnemonic word at position 5.` (code `INVALID_WORD`, `details.position`). Other error messages are unchanged.
- Argument errors (thresholds, counts, master secret, passphrase) are now `ShamirError` instances instead of plain `Error`. They are still `instanceof Error` and keep their messages, but their `name` is now `'ShamirError'`.
- Generation parameters are validated: non-integer or `NaN` thresholds and counts, an iteration exponent outside 0 to 15, an identifier outside 0 to 32767 and a master secret that is not a `Buffer` are rejected. Before, some of these produced shares that silently recovered a wrong secret.
- Thresholds and counts must be numbers: numeric strings such as `'2'` are now rejected (`INVALID_THRESHOLD`, `INVALID_SHARE_COUNT`). In 1.2.0 they were accepted, and a string group threshold produced shares that recovered a wrong secret. Convert with `Number()` first.
- `encrypt` and `decrypt` validate the iteration exponent and the identifier.
- A share with the same index as an already added share but a different value is rejected (`CONFLICTING_SHARE`). Before, recovery could get stuck.
- The same share entered twice counts once, as in the Python reference implementation: a repeated share no longer makes `combineMnemonics` fail with a wrong number of mnemonics.
- `recoverEms` rejects a map containing an empty `ShareGroup` (`EMPTY_SHARES`).
- Leading and trailing whitespace in a mnemonic is ignored, and `combineMnemonics` accepts any iterable, including generators.
- `WORDLIST` is frozen and `WORD_INDEX` throws on `set`, `delete` and `clear`.
- Node.js 18 or later is required.
- The package no longer ships source maps or stale build files.
- Project renamed to Seedcase (author, license, security contact, repository URLs).

### Security

- Error messages no longer echo an unknown word: a share pasted without spaces could previously end up whole in an error message. Checksum, padding and grouping errors still quote the first 3 or 4 words, which only encode metadata.
- Intermediate halves of the Feistel cipher are wiped after each round.
- A too large iteration exponent is rejected before key derivation, which could otherwise block for minutes.

## Earlier versions

See the [git history](https://github.com/seedcaseio/shamir-mnemonic-ts/commits/main).
