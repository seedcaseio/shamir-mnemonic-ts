import { GROUP_PREFIX_LENGTH_WORDS } from './constants';
import { ShareGroup, recoverEms } from './shamir';
import { Share, ShareCommonParameters } from './share';
import { INSPECT_CUSTOM, MnemonicError, Passphrase, ShamirError } from './utils';

export const UNDETERMINED = -1;

export class RecoveryState {
  /** Object for keeping track of running Shamir recovery. */
  private lastShare: Share | null = null;
  private groups: Map<number, ShareGroup> = new Map();
  private parameters: ShareCommonParameters | null = null;

  groupPrefix(groupIndex: number): string {
    /** Return three starting words of a given group. */
    if (!this.lastShare) {
      throw new ShamirError('Add at least one share first', 'RECOVERY_NOT_STARTED');
    }

    // Create a fake share with the requested group index
    const fakeShare = new Share(
      this.lastShare.identifier,
      this.lastShare.extendable,
      this.lastShare.iterationExponent,
      groupIndex,
      this.lastShare.groupThreshold,
      this.lastShare.groupCount,
      this.lastShare.index,
      this.lastShare.memberThreshold,
      this.lastShare.value
    );
    return fakeShare.words().slice(0, GROUP_PREFIX_LENGTH_WORDS).join(' ');
  }

  groupStatus(groupIndex: number): [number, number] {
    /** Return completion status of given group.
     *
     * Result consists of the number of shares already entered, and the threshold
     * for recovering the group.
     */
    const group = this.groups.get(groupIndex);
    if (!group || group.isEmpty) {
      return [0, UNDETERMINED];
    }

    return [group.length, group.memberThreshold()];
  }

  groupIsComplete(groupIndex: number): boolean {
    /** Check whether a given group is already complete. */
    const group = this.groups.get(groupIndex);
    return group ? group.isComplete() : false;
  }

  groupsComplete(): number {
    /** Return the number of groups that are already complete. */
    if (this.parameters === null) {
      return 0;
    }

    let count = 0;
    for (let i = 0; i < this.parameters.groupCount; i++) {
      if (this.groupIsComplete(i)) {
        count++;
      }
    }
    return count;
  }

  isComplete(): boolean {
    /** Check whether the recovery set is complete.
     *
     * That is, at least M groups must be complete, where M is the global threshold.
     */
    if (this.parameters === null) {
      return false;
    }
    return this.groupsComplete() >= this.parameters.groupThreshold;
  }

  matches(share: Share): boolean {
    /** Check whether the provided share matches the current set, i.e., has the same
     * common parameters.
     */
    if (this.parameters === null) {
      return true;
    }
    const shareParams = share.commonParameters();
    return (
      shareParams.identifier === this.parameters.identifier &&
      shareParams.extendable === this.parameters.extendable &&
      shareParams.iterationExponent === this.parameters.iterationExponent &&
      shareParams.groupThreshold === this.parameters.groupThreshold &&
      shareParams.groupCount === this.parameters.groupCount
    );
  }

  addShare(share: Share): boolean {
    /** Add a share to the recovery set. */
    if (!this.matches(share)) {
      throw new MnemonicError(
        'This mnemonic is not part of the current set. Please try again.',
        'NOT_IN_CURRENT_SET'
      );
    }

    if (!this.groups.has(share.groupIndex)) {
      this.groups.set(share.groupIndex, new ShareGroup());
    }
    const group = this.groups.get(share.groupIndex)!;
    group.add(share);
    this.lastShare = share;

    if (this.parameters === null) {
      this.parameters = share.commonParameters();
    }

    return true;
  }

  has(obj: Share): boolean {
    if (!this.matches(obj)) {
      return false;
    }

    if (this.groups.size === 0) {
      return false;
    }

    const group = this.groups.get(obj.groupIndex);
    return group ? group.has(obj) : false;
  }

  /** JSON and console output show progress only, never share values. */
  toJSON(): { parameters: ShareCommonParameters | null; groups: { groupIndex: number; shareCount: number }[] } {
    return {
      parameters: this.parameters,
      groups: Array.from(this.groups, ([groupIndex, group]) => ({ groupIndex, shareCount: group.length })),
    };
  }

  [INSPECT_CUSTOM](): string {
    return `RecoveryState ${JSON.stringify(this.toJSON())}`;
  }

  /**
   * Recover the master secret, given a passphrase.
   * @param passphrase The passphrase used to encrypt the master secret (string or UTF-8 Buffer).
   * @return The master secret.
   * @security The returned buffer contains sensitive data. Callers MUST clean it up
   *           using secureBufferFill() after use to prevent memory leaks.
   */
  recover(passphrase: Passphrase): Buffer {
    // Select a subset of shares which meets the thresholds.
    const reducedGroups: Map<number, ShareGroup> = new Map();
    
    for (const [groupIndex, group] of this.groups.entries()) {
      if (group.isComplete()) {
        reducedGroups.set(groupIndex, group.getMinimalGroup());
      }

      // some groups have been added so parameters must be known
      if (this.parameters === null) {
        throw new Error('Parameters should be known at this point');
      }
      
      if (reducedGroups.size >= this.parameters.groupThreshold) {
        break;
      }
    }

    const encryptedMasterSecret = recoverEms(reducedGroups);
    return encryptedMasterSecret.decrypt(passphrase);
  }
}
