import type { DatasetCore, Quad } from '@rdfjs/types';

/**
 * An interface for the external class that contains the necessary information
 * required by the policy engines in this library.
 */
export interface AuthorizationManager {
  /**
   * Returns the parent resource for the given identifier.
   * Should return `undefined` if no such parent exists.
   *
   * @param id - The target to find the parent of.
   */
  getParent: (id: string) => string | undefined;

  /**
   * Returns the relevant authorization data for the given identifier.
   * The type of data that needs to be returned depends on the authorization metadata being used.
   * E.g., in the case of WAC, this would be the contents of the corresponding ACL resource.
   * Should return `undefined` if there is no relevant authorization.
   * Again in the case of WAC, this would correspond to no corresponding ACL resource existing.
   *
   * @param id - Identifier to get the relevant authorization data for.
   */
  getAuthorizationData: (id: string) => Promise<DatasetCore | Quad[] | undefined>;
}
