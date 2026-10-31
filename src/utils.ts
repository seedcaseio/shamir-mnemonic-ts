/**
 * Stable error codes. Apps should switch on `code` (and read `details`) to show
 * their own translated messages, never parse `message`, which may change.
 */
export type ShamirErrorCode =
  // Invalid mnemonic or set of mnemonics (thrown as MnemonicError)
  | 'INVALID_MNEMONIC'
  | 'INVALID_WORD'
  | 'MNEMONIC_TOO_SHORT'
  | 'INVALID_MNEMONIC_LENGTH'
  | 'INVALID_CHECKSUM'
  | 'INVALID_PADDING'
  | 'GROUP_THRESHOLD_EXCEEDS_GROUP_COUNT'
  | 'PARAMETERS_MISMATCH'
  | 'MIXED_MNEMONIC_SETS'
  | 'DUPLICATE_SHARE_INDEX'
  | 'CONFLICTING_SHARE'
  | 'SHARE_LENGTH_MISMATCH'
  | 'INVALID_DIGEST'
  | 'EMPTY_MNEMONICS'
  | 'EMPTY_SHARES'
  | 'INSUFFICIENT_GROUPS'
  | 'WRONG_GROUP_COUNT'
  | 'WRONG_MEMBER_COUNT'
  | 'NOT_IN_CURRENT_SET'
  // Invalid arguments or state (thrown as ShamirError)
  | 'INVALID_THRESHOLD'
  | 'THRESHOLD_EXCEEDS_SHARE_COUNT'
  | 'INVALID_SHARE_COUNT'
  | 'TOO_MANY_SHARES'
  | 'GROUP_THRESHOLD_EXCEEDS_GROUPS'
  | 'MEMBER_THRESHOLD_ONE_NOT_ALLOWED'
  | 'MASTER_SECRET_TOO_SHORT'
  | 'MASTER_SECRET_ODD_LENGTH'
  | 'INVALID_MASTER_SECRET'
  | 'INVALID_ITERATION_EXPONENT'
  | 'INVALID_IDENTIFIER'
  | 'PASSPHRASE_NOT_PRINTABLE_ASCII'
  | 'PASSPHRASE_NOT_UTF8'
  | 'INVALID_PASSPHRASE'
  | 'RECOVERY_NOT_STARTED';

/** Extra error data. Only metadata (counts, positions, field names), never secret material. */
export type ShamirErrorDetails = Readonly<Record<string, string | number>>;

/** Base class of every error thrown on purpose by this library. */
export class ShamirError extends Error {
  readonly code: ShamirErrorCode;
  readonly details: ShamirErrorDetails;

  constructor(message: string, code: ShamirErrorCode, details: ShamirErrorDetails = {}) {
    super(message);
    this.name = 'ShamirError';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

/** An invalid mnemonic or set of mnemonics (user input). */
export class MnemonicError extends ShamirError {
  constructor(message = '', code: ShamirErrorCode = 'INVALID_MNEMONIC', details: ShamirErrorDetails = {}) {
    super(message, code, details);
    this.name = 'MnemonicError';
  }
}

/**
 * Key of Node's custom inspect hook (used by console.log and util.inspect).
 * Defined with Symbol.for so no Node import is needed (keeps `./decode` usable outside Node).
 */
export const INSPECT_CUSTOM: unique symbol = Symbol.for('nodejs.util.inspect.custom');

/** Placeholder shown instead of secret bytes in logs and JSON. */
export const REDACTED = '[redacted]';

/** Get the number of `radixBits`-sized digits required to store a `n`-bit value. */
function _roundBits(n: number, radixBits: number): number {
  return Math.ceil(n / radixBits);
}

/** Round up bit count to whole bytes. */
export function bitsToBytes(n: number): number {
  return _roundBits(n, 8);
}

/** Round up bit count to a multiple of word size. */
export function bitsToWords(n: number): number {
  // Import constants here to handle circular dependency
  // This will work as long as calls to bitsToWords only happen *after* RADIX_BITS are declared
  const { RADIX_BITS } = require('./constants');
  
  if (!RADIX_BITS) {
    throw new Error('Declare RADIX_BITS *before* calling this');
  }

  return _roundBits(n, RADIX_BITS);
}

/** Convert an integer value to indices in big endian order. */
export function* intToIndices(value: number, length: number, radixBits: number): Generator<number> {
  const mask = (1 << radixBits) - 1;
  for (let i = length - 1; i >= 0; i--) {
    yield (value >> (i * radixBits)) & mask;
  }
}

/**
 * Constant-time buffer comparison to prevent timing attacks.
 * Returns true if buffers are equal, false otherwise.
 * Always takes the same amount of time regardless of buffer contents.
 */
export function constantTimeEquals(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    // Still perform comparison to maintain constant time
    let dummy = 0;
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      dummy |= a[i] ^ b[i];
    }
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Creates an independent copy of a buffer (or portion of it).
 * Use this instead of .slice() when working with sensitive data.
 */
export function secureBufferCopy(
  source: Buffer,
  start: number = 0,
  end?: number
): Buffer {
  const endIndex = end !== undefined ? end : source.length;
  const length = endIndex - start;
  const copy = Buffer.allocUnsafe(length);
  source.copy(copy, 0, start, endIndex);
  return copy;
}

/**
 * Securely overwrites a buffer with zeros.
 * Note: In JavaScript, this doesn't guarantee memory is cleared
 * (due to GC), but it's a best practice.
 */
export function secureBufferFill(buffer: Buffer, value: number = 0): void {
  buffer.fill(value);
}

export type Passphrase = string | Buffer;

/**
 * Normalizes a passphrase (string or Buffer) to a Buffer for internal use.
 * - If a string is passed, it is encoded as UTF-8.
 * - If a Buffer is passed, it must contain valid UTF-8; otherwise an Error is thrown.
 * @param passphrase The passphrase as a string or UTF-8-encoded Buffer.
 * @returns The passphrase as a Buffer.
 */
export function normalizePassphrase(passphrase: Passphrase): Buffer {
  if (typeof passphrase === 'string') {
    return Buffer.from(passphrase, 'utf8');
  }
  if (!Buffer.isBuffer(passphrase)) {
    throw new ShamirError('The passphrase must be a string or a Buffer.', 'INVALID_PASSPHRASE');
  }
  // Buffer: verify it is valid UTF-8 (round-trip check)
  const roundTrip = Buffer.from(passphrase.toString('utf8'), 'utf8');
  if (roundTrip.compare(passphrase) !== 0) {
    throw new ShamirError(
      'The passphrase buffer must contain valid UTF-8 when provided as a Buffer.',
      'PASSPHRASE_NOT_UTF8'
    );
  }
  return passphrase;
}
