import type { AccessControlResource } from './Acp';

/**
 * A class that can be used to find the relevant ACP Access Control Resources for a given target.
 */
export interface AcpRepository {
  /**
   * Returns the relevant ACRs for the given target.
   */
  getRelevantACRs: (target: string) => AsyncGenerator<AccessControlResource, void>;
}
