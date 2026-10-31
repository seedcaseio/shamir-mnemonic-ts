import * as crypto from 'crypto';
import {
  BASE_ITERATION_COUNT,
  CUSTOMIZATION_STRING_ORIG,
  ID_LENGTH_BITS,
  ITERATION_EXP_LENGTH_BITS,
  ROUND_COUNT,
} from './constants';
import { ShamirError, bitsToBytes, secureBufferCopy, secureBufferFill } from './utils';

/**
 * Both values are packed into fixed-width bit fields of the share: out of range,
 * they would silently corrupt neighbouring fields and give unrecoverable shares.
 * A large exponent would also block PBKDF2 for minutes (or overflow the iteration count).
 */
export function assertIterationExponent(iterationExponent: number): void {
  const max = (1 << ITERATION_EXP_LENGTH_BITS) - 1;
  if (!Number.isInteger(iterationExponent) || iterationExponent < 0 || iterationExponent > max) {
    throw new ShamirError(
      `The iteration exponent must be an integer between 0 and ${max}.`,
      'INVALID_ITERATION_EXPONENT',
      { max }
    );
  }
}

export function assertIdentifier(identifier: number): void {
  const max = (1 << ID_LENGTH_BITS) - 1;
  if (!Number.isInteger(identifier) || identifier < 0 || identifier > max) {
    throw new ShamirError(
      `The identifier must be an integer between 0 and ${max}.`,
      'INVALID_IDENTIFIER',
      { max }
    );
  }
}

function _xor(a: Buffer, b: Buffer): Buffer {
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

function _roundFunction(
  i: number,
  passphrase: Buffer,
  e: number,
  salt: Buffer,
  r: Buffer
): Buffer {
  /** The round function used internally by the Feistel cipher. */
  const iBuffer = Buffer.from([i]);
  const passphraseConcat = Buffer.concat([iBuffer, passphrase]);
  const saltConcat = Buffer.concat([salt, r]);
  
  const result = crypto.pbkdf2Sync(
    passphraseConcat,
    saltConcat,
    (BASE_ITERATION_COUNT << e) / ROUND_COUNT,
    r.length,
    'sha256'
  );
  
  // Clean up temporary buffers containing sensitive data
  secureBufferFill(iBuffer);
  secureBufferFill(passphraseConcat);
  secureBufferFill(saltConcat);
  
  return result;
}

function _getSalt(identifier: number, extendable: boolean): Buffer {
  if (extendable) {
    return Buffer.alloc(0);
  }
  const identifierLen = bitsToBytes(ID_LENGTH_BITS);
  const identifierBuf = Buffer.allocUnsafe(identifierLen);
  identifierBuf.writeUIntBE(identifier, 0, identifierLen);
  return Buffer.concat([CUSTOMIZATION_STRING_ORIG, identifierBuf]);
}

export function encrypt(
  masterSecret: Buffer,
  passphrase: Buffer,
  iterationExponent: number,
  identifier: number,
  extendable: boolean
): Buffer {
  assertIterationExponent(iterationExponent);
  assertIdentifier(identifier);
  if (masterSecret.length % 2 !== 0) {
    throw new ShamirError(
      'The length of the master secret in bytes must be an even number.',
      'MASTER_SECRET_ODD_LENGTH'
    );
  }

  let l: Buffer = secureBufferCopy(masterSecret, 0, masterSecret.length / 2);
  let r: Buffer = secureBufferCopy(masterSecret, masterSecret.length / 2);
  const salt = _getSalt(identifier, extendable);

  for (let i = 0; i < ROUND_COUNT; i++) {
    const f = _roundFunction(i, passphrase, iterationExponent, salt, r);
    const temp = l;
    l = r;
    r = _xor(temp, f);
    // Clean up f (derived from the passphrase) and temp (in round 0, half of the plaintext secret)
    secureBufferFill(f);
    secureBufferFill(temp);
  }

  const result = Buffer.concat([r, l]);
  
  // Clean up temporary buffers after creating result
  secureBufferFill(l);
  secureBufferFill(r);

  return result;
}

export function decrypt(
  encryptedMasterSecret: Buffer,
  passphrase: Buffer,
  iterationExponent: number,
  identifier: number,
  extendable: boolean
): Buffer {
  assertIterationExponent(iterationExponent);
  assertIdentifier(identifier);
  if (encryptedMasterSecret.length % 2 !== 0) {
    throw new ShamirError(
      'The length of the encrypted master secret in bytes must be an even number.',
      'MASTER_SECRET_ODD_LENGTH'
    );
  }

  let l: Buffer = secureBufferCopy(encryptedMasterSecret, 0, encryptedMasterSecret.length / 2);
  let r: Buffer = secureBufferCopy(encryptedMasterSecret, encryptedMasterSecret.length / 2);
  const salt = _getSalt(identifier, extendable);

  for (let i = ROUND_COUNT - 1; i >= 0; i--) {
    const f = _roundFunction(i, passphrase, iterationExponent, salt, r);
    const temp = l;
    l = r;
    r = _xor(temp, f);
    // Clean up f (derived from the passphrase) and temp (intermediate cipher state)
    secureBufferFill(f);
    secureBufferFill(temp);
  }

  const result = Buffer.concat([r, l]);
  
  // Clean up temporary buffers after creating result
  secureBufferFill(l);
  secureBufferFill(r);

  return result;
}
