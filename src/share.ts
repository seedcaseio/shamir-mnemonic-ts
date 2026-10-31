import * as rs1024 from './rs1024';
import * as wordlist from './wordlist';
import {
  CUSTOMIZATION_STRING_EXTENDABLE,
  CUSTOMIZATION_STRING_ORIG,
  EXTENDABLE_FLAG_LENGTH_BITS,
  ID_EXP_LENGTH_WORDS,
  ITERATION_EXP_LENGTH_BITS,
  METADATA_LENGTH_WORDS,
  MIN_MNEMONIC_LENGTH_WORDS,
  RADIX,
  RADIX_BITS,
} from './constants';
import { INSPECT_CUSTOM, MnemonicError, REDACTED, bitsToBytes, bitsToWords, intToIndices } from './utils';

export type WordIndex = number;

function _intToWordIndices(value: number, length: number): WordIndex[] {
  /** Converts an integer value to a list of base 1024 indices in big endian order. */
  return Array.from(intToIndices(value, length, RADIX_BITS));
}

function _intFromWordIndices(indices: Iterable<WordIndex>): number {
  /** Converts a list of base 1024 indices in big endian order to an integer value. */
  let value = 0;
  for (const index of indices) {
    value = value * RADIX + index;
  }
  return value;
}

function _customizationString(extendable: boolean): Buffer {
  return extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG;
}

export interface ShareCommonParameters {
  /** Parameters that are common to all shares of a master secret. */
  identifier: number;
  extendable: boolean;
  iterationExponent: number;
  groupThreshold: number;
  groupCount: number;
}

export interface ShareGroupParameters {
  /** Parameters that are common to all shares of a master secret, which belong to the same group. */
  identifier: number;
  extendable: boolean;
  iterationExponent: number;
  groupIndex: number;
  groupThreshold: number;
  groupCount: number;
  memberThreshold: number;
}

export class Share {
  readonly identifier: number;
  readonly extendable: boolean;
  readonly iterationExponent: number;
  readonly groupIndex: number;
  readonly groupThreshold: number;
  readonly groupCount: number;
  readonly index: number;
  readonly memberThreshold: number;
  readonly value: Buffer;

  constructor(
    identifier: number,
    extendable: boolean,
    iterationExponent: number,
    groupIndex: number,
    groupThreshold: number,
    groupCount: number,
    index: number,
    memberThreshold: number,
    value: Buffer
  ) {
    this.identifier = identifier;
    this.extendable = extendable;
    this.iterationExponent = iterationExponent;
    this.groupIndex = groupIndex;
    this.groupThreshold = groupThreshold;
    this.groupCount = groupCount;
    this.index = index;
    this.memberThreshold = memberThreshold;
    this.value = value;
  }

  commonParameters(): ShareCommonParameters {
    /** Return values that uniquely identify a matching set of shares. */
    return {
      identifier: this.identifier,
      extendable: this.extendable,
      iterationExponent: this.iterationExponent,
      groupThreshold: this.groupThreshold,
      groupCount: this.groupCount,
    };
  }

  groupParameters(): ShareGroupParameters {
    /** Return values that uniquely identify shares belonging to the same group. */
    return {
      identifier: this.identifier,
      extendable: this.extendable,
      iterationExponent: this.iterationExponent,
      groupIndex: this.groupIndex,
      groupThreshold: this.groupThreshold,
      groupCount: this.groupCount,
      memberThreshold: this.memberThreshold,
    };
  }

  _encodeIdExp(): WordIndex[] {
    let idExpInt = this.identifier << (ITERATION_EXP_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS);
    idExpInt += (this.extendable ? 1 : 0) << ITERATION_EXP_LENGTH_BITS;
    idExpInt += this.iterationExponent;
    return _intToWordIndices(idExpInt, ID_EXP_LENGTH_WORDS);
  }

  _encodeShareParams(): WordIndex[] {
    // each value is 4 bits, for 20 bits total
    let val = this.groupIndex;
    val <<= 4;
    val += this.groupThreshold - 1;
    val <<= 4;
    val += this.groupCount - 1;
    val <<= 4;
    val += this.index;
    val <<= 4;
    val += this.memberThreshold - 1;
    // group parameters are 2 words
    return _intToWordIndices(val, 2);
  }

  words(): string[] {
    /** Convert share data to a share mnemonic. */
    const valueWordCount = bitsToWords(this.value.length * 8);
    // Convert Buffer to big-endian integer (using BigInt to handle large values)
    let valueInt = 0n;
    for (let i = 0; i < this.value.length; i++) {
      valueInt = (valueInt << 8n) | BigInt(this.value[i]);
    }
    // Convert BigInt to number array for _intToWordIndices
    // For very large values, we need to handle this differently
    const valueData: WordIndex[] = [];
    let tempValue = valueInt;
    for (let i = 0; i < valueWordCount; i++) {
      valueData.unshift(Number(tempValue & 1023n));
      tempValue = tempValue >> 10n;
    }

    const shareData = this._encodeIdExp().concat(this._encodeShareParams()).concat(valueData);
    const checksum = rs1024.createChecksum(shareData, _customizationString(this.extendable));

    return Array.from(wordlist.wordsFromIndices(shareData.concat(checksum)));
  }

  mnemonic(): string {
    /** Convert share data to a share mnemonic. */
    return this.words().join(' ');
  }

  /** JSON and console output show the metadata only, never the share value. */
  toJSON(): ShareGroupParameters & { index: number; value: string } {
    return { ...this.groupParameters(), index: this.index, value: REDACTED };
  }

  [INSPECT_CUSTOM](): string {
    return `Share ${JSON.stringify(this.toJSON())}`;
  }

  static fromMnemonic(mnemonic: string): Share {
    /** Convert a share mnemonic to share data. */
    const mnemonicData = wordlist.mnemonicToIndices(mnemonic);

    if (mnemonicData.length < MIN_MNEMONIC_LENGTH_WORDS) {
      throw new MnemonicError(
        `Invalid mnemonic length. The length of each mnemonic ` +
        `must be at least ${MIN_MNEMONIC_LENGTH_WORDS} words.`,
        'MNEMONIC_TOO_SHORT',
        { minWords: MIN_MNEMONIC_LENGTH_WORDS }
      );
    }

    const paddingLen = (RADIX_BITS * (mnemonicData.length - METADATA_LENGTH_WORDS)) % 16;
    if (paddingLen > 8) {
      throw new MnemonicError('Invalid mnemonic length.', 'INVALID_MNEMONIC_LENGTH');
    }

    const idExpData = mnemonicData.slice(0, ID_EXP_LENGTH_WORDS);
    const idExpInt = _intFromWordIndices(idExpData);

    const identifier = idExpInt >> (EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS);
    const extendable = Boolean((idExpInt >> ITERATION_EXP_LENGTH_BITS) & 1);
    const iterationExponent = idExpInt & ((1 << ITERATION_EXP_LENGTH_BITS) - 1);

    if (!rs1024.verifyChecksum(mnemonicData, _customizationString(extendable))) {
      const prefix = mnemonic.trim().split(/\s+/).slice(0, ID_EXP_LENGTH_WORDS + 2).join(' ');
      throw new MnemonicError(
        `Invalid mnemonic checksum for "${prefix} ...".`,
        'INVALID_CHECKSUM'
      );
    }

    const shareParamsData = mnemonicData.slice(ID_EXP_LENGTH_WORDS, ID_EXP_LENGTH_WORDS + 2);
    const shareParamsInt = _intFromWordIndices(shareParamsData);
    const shareParams = Array.from(intToIndices(shareParamsInt, 5, 4));
    const [
      groupIndex,
      groupThreshold,
      groupCount,
      index,
      memberThreshold,
    ] = shareParams;

    if (groupCount < groupThreshold) {
      const prefix = mnemonic.trim().split(/\s+/).slice(0, ID_EXP_LENGTH_WORDS + 2).join(' ');
      throw new MnemonicError(
        `Invalid mnemonic "${prefix} ...". Group threshold cannot be greater than group count.`,
        'GROUP_THRESHOLD_EXCEEDS_GROUP_COUNT'
      );
    }

    const valueData = mnemonicData.slice(
      ID_EXP_LENGTH_WORDS + 2,
      mnemonicData.length - rs1024.CHECKSUM_LENGTH_WORDS
    );
    const valueByteCount = bitsToBytes(RADIX_BITS * valueData.length - paddingLen);
    
    // Convert word indices to BigInt (base 1024)
    let valueInt = 0n;
    for (const index of valueData) {
      valueInt = valueInt * 1024n + BigInt(index);
    }
    
    // Convert BigInt to Buffer in big-endian format
    let value: Buffer;
    try {
      value = Buffer.allocUnsafe(valueByteCount);
      let tempValue = valueInt;
      for (let i = valueByteCount - 1; i >= 0; i--) {
        value[i] = Number(tempValue & 0xFFn);
        tempValue = tempValue >> 8n;
      }

      if (tempValue !== 0n) {
        const prefix = mnemonic.trim().split(/\s+/).slice(0, ID_EXP_LENGTH_WORDS + 2).join(' ');
        throw new MnemonicError(
          `Invalid mnemonic padding for "${prefix} ...".`,
          'INVALID_PADDING'
        );
      }
    } catch (error) {
      if (error instanceof MnemonicError) {
        throw error;
      }
      const prefix = mnemonic.trim().split(/\s+/).slice(0, ID_EXP_LENGTH_WORDS + 2).join(' ');
      throw new MnemonicError(
        `Invalid mnemonic padding for "${prefix} ...".`,
        'INVALID_PADDING'
      );
    }

    return new Share(
      identifier,
      extendable,
      iterationExponent,
      groupIndex,
      groupThreshold + 1,
      groupCount + 1,
      index,
      memberThreshold + 1,
      value
    );
  }
}
