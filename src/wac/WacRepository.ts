import type { WacAuthorization } from './WacAuthorization';

/**
 * A class that can be used to find the relevant WAC authorization objects for a given target.
 */
export interface WacRepository {
  /**
   * Returns the relevant WAC authorization objects for the given target.
   */
  getRelevantAuthorizations: (target: string) => AsyncGenerator<WacAuthorization, void>;
}
