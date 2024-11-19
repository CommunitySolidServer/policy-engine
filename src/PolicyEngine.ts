import type { NamedNode, Quad } from '@rdfjs/types';
import type { Credentials } from './Credentials';

export type PermissionMap = Record<string, boolean>;

export type PolicyReport = { id: NamedNode; quads: Quad[] };

export type PermissionReport = PolicyReport & { permissions: PermissionMap };

/**
 * Determines the available permissions for the given credentials,
 * potentially with a report describing why permissions were granted or denied.
 */
export interface PolicyEngine {
  /**
   * Returns the granted and denied permissions for the given input.
   *
   * @param target - Identifier of the targeted resource.
   * @param credentials - Credentials identifying who or what is trying to access the target resource.
   * @param permissions - Optional list of permissions that are being requested.
   *                      As an optimization, the engine can look at just those that are requested.
   */
  getPermissions: (target: string, credentials: Credentials, permissions?: string[]) => Promise<PermissionMap>;

  /**
   * Returns the granted and denied permissions for the given input.
   * This also generates a report describing why permissions were granted or denied.
   *
   * @param target - Identifier of the targeted resource.
   * @param credentials - Credentials identifying who or what is trying to access the target resource.
   * @param permissions - Optional list of permissions that are being requested.
   *                      As an optimization, the engine can look at just those that are requested.
   */
  getPermissionsWithReport: (target: string, credentials: Credentials, permissions?: string[]) =>
  Promise<PermissionReport>;
}
