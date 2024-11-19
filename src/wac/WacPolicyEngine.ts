import { getLoggerFor } from 'global-logger-factory';
import type { Credentials } from '../Credentials';
import type { PermissionMap, PermissionReport, PolicyEngine } from '../PolicyEngine';
import type { AccessChecker } from './access/AccessChecker';
import type { WacAuthValidation } from './WacAuthValidation';
import type { WacRepository } from './WacRepository';
import type { WacPermissionMap } from './WacUtil';
import { generateWacReport, isSuccessfulAuthorization, removeWacReasons } from './WacUtil';

/**
 * A {@link PolicyEngine} that handles WAC authorization.
 */
export class WacPolicyEngine implements PolicyEngine {
  protected readonly logger = getLoggerFor(this);

  public constructor(
    protected readonly accessChecker: AccessChecker,
    protected readonly repository: WacRepository,
  ) {}

  public async getPermissions(target: string, credentials: Credentials, permissions?: string[]):
  Promise<PermissionMap> {
    const permissionMap = await this.generatePermissionMap(target, credentials, permissions);
    return removeWacReasons(permissionMap);
  }

  public async getPermissionsWithReport(target: string, credentials: Credentials, permissions?: string[]):
  Promise<PermissionReport> {
    const permissionMap = await this.generatePermissionMap(target, credentials, permissions);
    return {
      permissions: removeWacReasons(permissionMap),
      ...generateWacReport(permissionMap, target, credentials.agent),
    };
  }

  /**
   * Generates the permission map for the given target and context.
   */
  protected async generatePermissionMap(target: string, credentials: Credentials, permissions?: string[]):
  Promise<WacPermissionMap> {
    const permissionMap: Record<string, { reason: WacAuthValidation; allow: boolean }> = {};
    for await (const auth of this.repository.getRelevantAuthorizations(target)) {
      this.logger.debug(`Determining permissions for authorization ${auth.id.value}`);
      if (permissions && !auth.mode.some((mode): boolean => permissions.includes(mode.value))) {
        // Ignore policies that don't provide relevant information
        this.logger.debug(`Ignoring irrelevant authorization ${auth.id.value}`);
        continue;
      }
      const validation = await this.accessChecker.handleSafe({ auth, credentials });
      if (isSuccessfulAuthorization(validation)) {
        for (const mode of validation.auth.mode) {
          permissionMap[mode.value] = { reason: validation, allow: true };
        }
      }
    }
    return permissionMap;
  }
}
