import * as crypto from 'crypto';
import * as cipher from './cipher';
import {
  DIGEST_INDEX,
  DIGEST_LENGTH_BYTES,
  GROUP_PREFIX_LENGTH_WORDS,
  ID_EXP_LENGTH_WORDS,
  ID_LENGTH_BITS,
  MAX_SHARE_COUNT,
  MIN_STRENGTH_BITS,
  SECRET_INDEX,
} from './constants';
import { Share, ShareCommonParameters, ShareGroupParameters } from './share';
import { INSPECT_CUSTOM, MnemonicError, REDACTED, ShamirError, bitsToBytes, constantTimeEquals, normalizePassphrase, Passphrase, secureBufferCopy, secureBufferFill } from './utils';

export interface RawShare {
  x: number;
  data: Buffer;
}

export class ShareGroup {
  protected _shares: Set<Share> = new Set();

  [Symbol.iterator](): Iterator<Share> {
    return this._shares.values();
  }

  get length(): number {
    return this._shares.size;
  }

  get isEmpty(): boolean {
    return this._shares.size === 0;
  }

  has(obj: Share): boolean {
    // Check by value equality, not reference
    for (const share of this._shares) {
      if (
        share.identifier === obj.identifier &&
        share.extendable === obj.extendable &&
        share.iterationExponent === obj.iterationExponent &&
        share.groupIndex === obj.groupIndex &&
        share.groupThreshold === obj.groupThreshold &&
        share.groupCount === obj.groupCount &&
        share.index === obj.index &&
        share.memberThreshold === obj.memberThreshold &&
        constantTimeEquals(share.value, obj.value)
      ) {
        return true;
      }
    }
    return false;
  }

  add(share: Share): void {
    if (this._shares.size > 0 && !this._groupParametersMatch(share)) {
      const existing = Array.from(this._shares)[0];
      const existingParams = existing.groupParameters();
      const newParams = share.groupParameters();
      
      const fields: (keyof ShareGroupParameters)[] = [
        'identifier',
        'extendable',
        'iterationExponent',
        'groupIndex',
        'groupThreshold',
        'groupCount',
        'memberThreshold',
      ];
      
      for (const field of fields) {
        if (existingParams[field] !== newParams[field]) {
          throw new MnemonicError(
            `Invalid set of mnemonics. The ${field} parameters don't match.`,
            'PARAMETERS_MISMATCH',
            { field }
          );
        }
      }
    }

    // Shares are compared by value: the same share entered twice must count once.
    if (this.has(share)) {
      return;
    }
    // Same index, different value: two backups are mixed. Keeping both would make the
    // group look complete while recovery can never succeed.
    for (const existing of this._shares) {
      if (existing.index === share.index) {
        throw new MnemonicError(
          'Invalid set of shares. Another share with the same index but a different value was already added.',
          'CONFLICTING_SHARE',
          { index: share.index }
        );
      }
    }
    this._shares.add(share);
  }

  private _groupParametersMatch(share: Share): boolean {
    if (this._shares.size === 0) {
      return true;
    }
    const existing = Array.from(this._shares)[0];
    const existingParams = existing.groupParameters();
    const newParams = share.groupParameters();
    
    return (
      existingParams.identifier === newParams.identifier &&
      existingParams.extendable === newParams.extendable &&
      existingParams.iterationExponent === newParams.iterationExponent &&
      existingParams.groupIndex === newParams.groupIndex &&
      existingParams.groupThreshold === newParams.groupThreshold &&
      existingParams.groupCount === newParams.groupCount &&
      existingParams.memberThreshold === newParams.memberThreshold
    );
  }

  /** JSON and console output never show share values. */
  toJSON(): { shares: ReturnType<Share['toJSON']>[] } {
    return { shares: Array.from(this._shares, share => share.toJSON()) };
  }

  [INSPECT_CUSTOM](): string {
    return `ShareGroup ${JSON.stringify(this.toJSON())}`;
  }

  toRawShares(): RawShare[] {
    return Array.from(this._shares).map(s => ({ x: s.index, data: s.value }));
  }

  getMinimalGroup(): ShareGroup {
    const group = new ShareGroup();
    const sharesArray = Array.from(this._shares);
    const threshold = this.memberThreshold();
    group._shares = new Set(sharesArray.slice(0, threshold));
    return group;
  }

  commonParameters(): ShareCommonParameters {
    return Array.from(this._shares)[0].commonParameters();
  }

  groupParameters(): ShareGroupParameters {
    return Array.from(this._shares)[0].groupParameters();
  }

  memberThreshold(): number {
    return Array.from(this._shares)[0].memberThreshold;
  }

  isComplete(): boolean {
    if (this._shares.size === 0) {
      return false;
    }
    return this._shares.size >= this.memberThreshold();
  }
}

export class EncryptedMasterSecret {
  readonly identifier: number;
  readonly extendable: boolean;
  readonly iterationExponent: number;
  readonly ciphertext: Buffer;

  constructor(
    identifier: number,
    extendable: boolean,
    iterationExponent: number,
    ciphertext: Buffer
  ) {
    this.identifier = identifier;
    this.extendable = extendable;
    this.iterationExponent = iterationExponent;
    this.ciphertext = ciphertext;
  }

  /**
   * JSON and console output never show the ciphertext: with an empty passphrase,
   * anyone can decrypt it back to the master secret.
   */
  toJSON(): { identifier: number; extendable: boolean; iterationExponent: number; ciphertext: string } {
    return {
      identifier: this.identifier,
      extendable: this.extendable,
      iterationExponent: this.iterationExponent,
      ciphertext: REDACTED,
    };
  }

  [INSPECT_CUSTOM](): string {
    return `EncryptedMasterSecret ${JSON.stringify(this.toJSON())}`;
  }

  static fromMasterSecret(
    masterSecret: Buffer,
    passphrase: Buffer,
    identifier: number,
    extendable: boolean,
    iterationExponent: number
  ): EncryptedMasterSecret {
    const ciphertext = cipher.encrypt(
      masterSecret,
      passphrase,
      iterationExponent,
      identifier,
      extendable
    );
    return new EncryptedMasterSecret(
      identifier,
      extendable,
      iterationExponent,
      ciphertext
    );
  }

  /**
   * Decrypt the master secret using the passphrase.
   * @param passphrase The passphrase used to encrypt the master secret (string or UTF-8 Buffer).
   * @return The master secret.
   * @security The returned buffer contains sensitive data. Callers MUST overwrite it
   *           after use (for example `buffer.fill(0)`) to limit its exposure in memory.
   */
  decrypt(passphrase: Passphrase): Buffer {
    const passphraseBuf = normalizePassphrase(passphrase);
    return cipher.decrypt(
      this.ciphertext,
      passphraseBuf,
      this.iterationExponent,
      this.identifier,
      this.extendable
    );
  }
}

/** Source of random bytes for identifiers and shares: Node's cryptographically secure generator. */
export const RANDOM_BYTES = (length: number): Buffer => {
  return crypto.randomBytes(length);
};

function _precomputeExpLog(): [number[], number[]] {
  const exp: number[] = new Array(255).fill(0);
  const log: number[] = new Array(256).fill(0);

  let poly = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = poly;
    log[poly] = i;

    // Multiply poly by the polynomial x + 1.
    poly = (poly << 1) ^ poly;

    // Reduce poly by x^8 + x^4 + x^3 + x + 1.
    if (poly & 0x100) {
      poly ^= 0x11B;
    }
  }

  return [exp, log];
}

const [EXP_TABLE, LOG_TABLE] = _precomputeExpLog();

function _interpolate(shares: RawShare[], x: number): Buffer {
  /**
   * Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
   * @param shares The Shamir shares.
   * @param x The x coordinate of the result.
   * @return Evaluations of the polynomials in x.
   */
  const xCoordinates = new Set(shares.map(share => share.x));

  if (xCoordinates.size !== shares.length) {
    throw new MnemonicError('Invalid set of shares. Share indices must be unique.', 'DUPLICATE_SHARE_INDEX');
  }

  const shareValueLengths = new Set(shares.map(share => share.data.length));
  if (shareValueLengths.size !== 1) {
    throw new MnemonicError(
      'Invalid set of shares. All share values must have the same length.',
      'SHARE_LENGTH_MISMATCH'
    );
  }

  if (xCoordinates.has(x)) {
    for (const share of shares) {
      if (share.x === x) {
        return secureBufferCopy(share.data);
      }
    }
  }

  // Logarithm of the product of (x_i - x) for i = 1, ... , k.
  let logProd = 0;
  for (const share of shares) {
    logProd = (logProd + LOG_TABLE[share.x ^ x]) % 255;
  }

  const resultLength = Array.from(shareValueLengths)[0];
  const result = Buffer.alloc(resultLength);

  for (const share of shares) {
    // The logarithm of the Lagrange basis polynomial evaluated at x.
    let logBasisEval = logProd;
    logBasisEval = (logBasisEval - LOG_TABLE[share.x ^ x] + 255) % 255;
    
    let sumOther = 0;
    for (const other of shares) {
      if (other.x !== share.x) {
        sumOther = (sumOther + LOG_TABLE[share.x ^ other.x]) % 255;
      }
    }
    logBasisEval = (logBasisEval - sumOther + 255) % 255;

    for (let i = 0; i < resultLength; i++) {
      const shareVal = share.data[i];
      if (shareVal !== 0) {
        result[i] ^= EXP_TABLE[(LOG_TABLE[shareVal] + logBasisEval) % 255];
      }
    }
  }

  return result;
}

function _createDigest(randomData: Buffer, sharedSecret: Buffer): Buffer {
  const hmac = crypto.createHmac('sha256', randomData);
  hmac.update(sharedSecret);
  const fullDigest = hmac.digest();
  const result = secureBufferCopy(fullDigest, 0, DIGEST_LENGTH_BYTES);
  return result;
}

function _splitSecret(
  threshold: number,
  shareCount: number,
  sharedSecret: Buffer
): RawShare[] {
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new ShamirError('The requested threshold must be a positive integer.', 'INVALID_THRESHOLD');
  }

  // Counts below 1 are caught by the threshold check below (previous behavior and message).
  if (!Number.isInteger(shareCount)) {
    throw new ShamirError('The requested number of shares must be a positive integer.', 'INVALID_SHARE_COUNT');
  }

  if (threshold > shareCount) {
    throw new ShamirError(
      'The requested threshold must not exceed the number of shares.',
      'THRESHOLD_EXCEEDS_SHARE_COUNT'
    );
  }

  if (shareCount > MAX_SHARE_COUNT) {
    throw new ShamirError(
      `The requested number of shares must not exceed ${MAX_SHARE_COUNT}.`,
      'TOO_MANY_SHARES',
      { max: MAX_SHARE_COUNT }
    );
  }

  // If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold === 1) {
    return Array.from({ length: shareCount }, (_, i) => ({
      x: i,
      data: secureBufferCopy(sharedSecret),
    }));
  }

  const randomShareCount = threshold - 2;

  const shares: RawShare[] = Array.from({ length: randomShareCount }, (_, i) => ({
    x: i,
    data: RANDOM_BYTES(sharedSecret.length),
  }));

  const randomPart = RANDOM_BYTES(sharedSecret.length - DIGEST_LENGTH_BYTES);
  const digest = _createDigest(randomPart, sharedSecret);

  const baseShares: RawShare[] = [
    ...shares,
    { x: DIGEST_INDEX, data: Buffer.concat([digest, randomPart]) },
    { x: SECRET_INDEX, data: sharedSecret },
  ];

  // Clean up randomPart and digest after they're copied into baseShares
  secureBufferFill(randomPart);
  secureBufferFill(digest);

  for (let i = randomShareCount; i < shareCount; i++) {
    shares.push({ x: i, data: _interpolate(baseShares, i) });
  }

  return shares;
}

function _recoverSecret(threshold: number, shares: RawShare[]): Buffer {
  // If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold === 1) {
    return secureBufferCopy(shares[0].data);
  }

  let sharedSecret: Buffer | undefined;
  let digestShare: Buffer | undefined;
  let digest: Buffer | undefined;
  let randomPart: Buffer | undefined;

  try {
    sharedSecret = _interpolate(shares, SECRET_INDEX);
    digestShare = _interpolate(shares, DIGEST_INDEX);
    digest = secureBufferCopy(digestShare, 0, DIGEST_LENGTH_BYTES);
    randomPart = secureBufferCopy(digestShare, DIGEST_LENGTH_BYTES);

    if (!constantTimeEquals(digest, _createDigest(randomPart, sharedSecret))) {
      // Clean up buffers before throwing error
      secureBufferFill(digest);
      secureBufferFill(randomPart);
      secureBufferFill(digestShare);
      throw new MnemonicError('Invalid digest of the shared secret.', 'INVALID_DIGEST');
    }

    // Clean up temporary buffers before returning
    secureBufferFill(digest);
    secureBufferFill(randomPart);
    secureBufferFill(digestShare);

    // Create a copy to return, original will be cleaned in finally
    const result = secureBufferCopy(sharedSecret);
    return result;
  } finally {
    // Ensure sharedSecret is cleaned even if an exception occurs
    if (sharedSecret !== undefined) {
      secureBufferFill(sharedSecret);
    }
    if (digestShare !== undefined) {
      secureBufferFill(digestShare);
    }
    if (digest !== undefined) {
      secureBufferFill(digest);
    }
    if (randomPart !== undefined) {
      secureBufferFill(randomPart);
    }
  }
}

export function decodeMnemonics(mnemonics: Iterable<string>): Map<number, ShareGroup> {
  const commonParams: ShareCommonParameters[] = [];
  const groups: Map<number, ShareGroup> = new Map();

  for (const mnemonic of mnemonics) {
    const share = Share.fromMnemonic(mnemonic);
    const params = share.commonParameters();
    commonParams.push(params);

    if (!groups.has(share.groupIndex)) {
      groups.set(share.groupIndex, new ShareGroup());
    }
    const group = groups.get(share.groupIndex)!;
    group.add(share);
  }

  if (commonParams.length === 0) {
    throw new MnemonicError('The list of mnemonics is empty.', 'EMPTY_MNEMONICS');
  }

  const firstParams = commonParams[0];
  for (const params of commonParams) {
    if (
      params.identifier !== firstParams.identifier ||
      params.extendable !== firstParams.extendable ||
      params.iterationExponent !== firstParams.iterationExponent ||
      params.groupThreshold !== firstParams.groupThreshold ||
      params.groupCount !== firstParams.groupCount
    ) {
      throw new MnemonicError(
        'Invalid set of mnemonics. ' +
        `All mnemonics must begin with the same ${ID_EXP_LENGTH_WORDS} words, ` +
        'must have the same group threshold and the same group count.',
        'MIXED_MNEMONIC_SETS',
        { wordCount: ID_EXP_LENGTH_WORDS }
      );
    }
  }

  return groups;
}

export function splitEms(
  groupThreshold: number,
  groups: Array<[number, number]>,
  encryptedMasterSecret: EncryptedMasterSecret
): Share[][] {
  /**
   * Split an Encrypted Master Secret into mnemonic shares.
   *
   * This function is a counterpart to `recoverEms`, and it is used as a subroutine in
   * `generateMnemonics`. The input is an *already encrypted* Master Secret (EMS), so it
   * is possible to encrypt the Master Secret in advance and perform the splitting later.
   *
   * @param groupThreshold The number of groups required to reconstruct the master secret.
   * @param groups A list of (member_threshold, member_count) pairs for each group, where member_count
   *   is the number of shares to generate for the group and member_threshold is the number of members required to
   *   reconstruct the group secret.
   * @param encryptedMasterSecret The encrypted master secret to split.
   * @return List of groups of shares (`Share` objects; call `mnemonic()` to get the words).
   */
  cipher.assertIdentifier(encryptedMasterSecret.identifier);
  cipher.assertIterationExponent(encryptedMasterSecret.iterationExponent);

  if (encryptedMasterSecret.ciphertext.length * 8 < MIN_STRENGTH_BITS) {
    throw new ShamirError(
      'The length of the master secret must be ' +
      `at least ${bitsToBytes(MIN_STRENGTH_BITS)} bytes.`,
      'MASTER_SECRET_TOO_SHORT',
      { minBytes: bitsToBytes(MIN_STRENGTH_BITS) }
    );
  }

  if (groupThreshold > groups.length) {
    throw new ShamirError(
      'The requested group threshold must not exceed the number of groups.',
      'GROUP_THRESHOLD_EXCEEDS_GROUPS'
    );
  }

  if (groups.some(([memberThreshold, memberCount]) => memberThreshold === 1 && memberCount > 1)) {
    throw new ShamirError(
      'Creating multiple member shares with member threshold 1 is not allowed. ' +
      'Use 1-of-1 member sharing instead.',
      'MEMBER_THRESHOLD_ONE_NOT_ALLOWED'
    );
  }

  const groupShares = _splitSecret(
    groupThreshold,
    groups.length,
    encryptedMasterSecret.ciphertext
  );

  return groups.map(([memberThreshold, memberCount], groupIndex) => {
    const groupSecret = groupShares[groupIndex].data;
    try {
      const memberShares = _splitSecret(memberThreshold, memberCount, groupSecret);

      return memberShares.map(({ x: memberIndex, data: value }) => {
        return new Share(
          encryptedMasterSecret.identifier,
          encryptedMasterSecret.extendable,
          encryptedMasterSecret.iterationExponent,
          groupIndex,
          groupThreshold,
          groups.length,
          memberIndex,
          memberThreshold,
          value
        );
      });
    } finally {
      secureBufferFill(groupSecret);
    }
  });
}

function _randomIdentifier(): number {
  /** Returns a random identifier with the given bit length. */
  const identifierBytes = RANDOM_BYTES(bitsToBytes(ID_LENGTH_BITS));
  let identifier = 0;
  for (let i = 0; i < identifierBytes.length; i++) {
    identifier = (identifier << 8) | identifierBytes[i];
  }
  // Mask to ID_LENGTH_BITS
  return identifier & ((1 << ID_LENGTH_BITS) - 1);
}

export function generateMnemonics(
  groupThreshold: number,
  groups: Array<[number, number]>,
  masterSecret: Buffer,
  passphrase: Passphrase = Buffer.alloc(0),
  extendable: boolean = true,
  iterationExponent: number = 1
): string[][] {
  /**
   * Split a master secret into mnemonic shares using Shamir's secret sharing scheme.
   *
   * The supplied Master Secret is encrypted by the passphrase (empty passphrase is used
   * if none is provided) and split into a set of mnemonic shares.
   *
   * This is the user-friendly method to back up a pre-existing secret with the Shamir
   * scheme, optionally protected by a passphrase.
   *
   * @param groupThreshold The number of groups required to reconstruct the master secret.
   * @param groups A list of (member_threshold, member_count) pairs for each group, where member_count
   *   is the number of shares to generate for the group and member_threshold is the number of members required to
   *   reconstruct the group secret.
   * @param masterSecret The master secret to split.
   * @param passphrase The passphrase used to encrypt the master secret (string or UTF-8 Buffer,
   *   printable ASCII only).
   * @param extendable Whether the shares can later be extended with new shares for the same
   *   secret (default true).
   * @param iterationExponent The encryption iteration exponent, an integer from 0 to 15 (default 1).
   *   Each step doubles the passphrase derivation cost.
   * @return List of groups of mnemonics.
   */
  if (!Buffer.isBuffer(masterSecret)) {
    throw new ShamirError('The master secret must be a Buffer.', 'INVALID_MASTER_SECRET');
  }
  // Checked before encryption: a large exponent would also block on PBKDF2 for minutes.
  cipher.assertIterationExponent(iterationExponent);

  const passphraseBuf = normalizePassphrase(passphrase);
  // Validate passphrase contains only printable ASCII characters (code points 32-126)
  for (let i = 0; i < passphraseBuf.length; i++) {
    const code = passphraseBuf[i];
    if (code < 32 || code > 126) {
      throw new ShamirError(
        'The passphrase must contain only printable ASCII characters (code points 32-126).',
        'PASSPHRASE_NOT_PRINTABLE_ASCII'
      );
    }
  }

  const identifier = _randomIdentifier();
  const encryptedMasterSecret = EncryptedMasterSecret.fromMasterSecret(
    masterSecret,
    passphraseBuf,
    identifier,
    extendable,
    iterationExponent
  );
  const groupedShares = splitEms(groupThreshold, groups, encryptedMasterSecret);
  return groupedShares.map(group => group.map(share => share.mnemonic()));
}

export function recoverEms(groups: Map<number, ShareGroup>): EncryptedMasterSecret {
  /**
   * Combine shares, recover metadata and the Encrypted Master Secret.
   *
   * This function is a counterpart to `splitEms`, and it is used as a subroutine in
   * `combineMnemonics`. It returns the EMS itself and data required for its decryption,
   * except for the passphrase. It is thus possible to defer decryption of the Master
   * Secret to a later time.
   *
   * @param groups Set of shares classified into groups.
   * @return Encrypted Master Secret
   */
  if (groups.size === 0 || Array.from(groups.values()).some(group => group.isEmpty)) {
    throw new MnemonicError('The set of shares is empty.', 'EMPTY_SHARES');
  }

  const firstGroup = Array.from(groups.values())[0];
  const params = firstGroup.commonParameters();

  if (groups.size < params.groupThreshold) {
    throw new MnemonicError(
      'Insufficient number of mnemonic groups. ' +
      `The required number of groups is ${params.groupThreshold}.`,
      'INSUFFICIENT_GROUPS',
      { required: params.groupThreshold }
    );
  }

  if (groups.size !== params.groupThreshold) {
    throw new MnemonicError(
      'Wrong number of mnemonic groups. ' +
      `Expected ${params.groupThreshold} groups, ` +
      `but ${groups.size} were provided.`,
      'WRONG_GROUP_COUNT',
      { expected: params.groupThreshold, provided: groups.size }
    );
  }

  for (const group of groups.values()) {
    if (group.length !== group.memberThreshold()) {
      const shareWords = Array.from(group)[0].words();
      const prefix = shareWords.slice(0, GROUP_PREFIX_LENGTH_WORDS).join(' ');
      throw new MnemonicError(
        'Wrong number of mnemonics. ' +
        `Expected ${group.memberThreshold()} mnemonics starting with "${prefix} ...", ` +
        `but ${group.length} were provided.`,
        'WRONG_MEMBER_COUNT',
        { expected: group.memberThreshold(), provided: group.length }
      );
    }
  }

  const groupShares: RawShare[] = Array.from(groups.entries()).map(([groupIndex, group]) => ({
    x: groupIndex,
    data: _recoverSecret(group.memberThreshold(), group.toRawShares()),
  }));

  const ciphertext = _recoverSecret(params.groupThreshold, groupShares);
  return new EncryptedMasterSecret(
    params.identifier,
    params.extendable,
    params.iterationExponent,
    ciphertext
  );
}

export function combineMnemonics(
  mnemonics: Iterable<string>,
  passphrase: Passphrase = Buffer.alloc(0)
): Buffer {
  /**
   * Combine mnemonic shares to obtain the master secret which was previously split
   * using Shamir's secret sharing scheme.
   *
   * This is the user-friendly method to recover a backed-up secret optionally protected
   * by a passphrase.
   *
   * @param mnemonics List of mnemonics.
   * @param passphrase The passphrase used to encrypt the master secret (string or UTF-8 Buffer).
   * @return The master secret.
   * @security The returned buffer contains sensitive data. Callers MUST overwrite it
   *           after use (for example `buffer.fill(0)`) to limit its exposure in memory.
   */
  // Materialize once: a generator would be exhausted by the emptiness check.
  const mnemonicList = mnemonics ? Array.from(mnemonics) : [];
  if (mnemonicList.length === 0) {
    throw new MnemonicError('The list of mnemonics is empty.', 'EMPTY_MNEMONICS');
  }

  const groups = decodeMnemonics(mnemonicList);
  const encryptedMasterSecret = recoverEms(groups);
  return encryptedMasterSecret.decrypt(passphrase);
}
