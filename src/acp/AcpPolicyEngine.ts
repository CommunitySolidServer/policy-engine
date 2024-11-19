import { randomUUID } from 'node:crypto';
import { getLoggerFor } from 'global-logger-factory';
import { DataFactory } from 'n3';
import type { Credentials } from '../Credentials';
import type { PermissionMap, PermissionReport, PolicyEngine } from '../PolicyEngine';
import type { Context, Policy } from './Acp';
import type { AcpPermissionMap } from './AcpEvalUtil';
import { isSuccessfulPolicy, removeAcpReasons, validatePolicy } from './AcpEvalUtil';
import { getEffectivePolicies } from './AcpParseUtil';
import { contextToQuads, generateAcpReport } from './AcpReportUtil';
import type { AcpRepository } from './AcpRepository';

/**
 * A {@link PolicyEngine} that handles ACP authorization.
 */
export class AcpPolicyEngine implements PolicyEngine {
  protected readonly logger = getLoggerFor(this);

  public constructor(protected readonly repository: AcpRepository) {}

  public async getPermissions(target: string, credentials: Credentials, permissions?: string[]):
  Promise<PermissionMap> {
    const context: Context = { target, ...credentials };

    const permissionMap = await this.generatePermissionMap(target, context, permissions);
    return removeAcpReasons(permissionMap);
  }

  public async getPermissionsWithReport(target: string, credentials: Credentials, permissions?: string[]):
  Promise<PermissionReport> {
    const context: Context = { target, ...credentials };

    const permissionMap = await this.generatePermissionMap(target, context, permissions);

    const contextId = DataFactory.namedNode(`urn:uuid:${randomUUID()}`);
    const result = generateAcpReport(contextId, permissionMap);
    result.quads.push(...contextToQuads(contextId, context));

    return {
      permissions: removeAcpReasons(permissionMap),
      ...result,
    };
  }

  /**
   * Generates the permission map for the given target and context.
   */
  protected async generatePermissionMap(target: string, context: Context, permissions?: string[]):
  Promise<AcpPermissionMap> {
    const result: AcpPermissionMap = {};
    for await (const acr of this.repository.getRelevantACRs(target)) {
      this.logger.debug(`Interpreting relevant ACR ${acr.iri}`);
      for (const policy of getEffectivePolicies(target, acr)) {
        this.logger.debug(`Interpreting effective policy ${policy.iri}`);
        // Ignore policies that don't provide relevant information
        if (!this.isRelevantPolicy(policy, result, permissions)) {
          this.logger.debug(`Skipping irrelevant policy ${policy.iri}`);
          continue;
        }

        const validated = validatePolicy(policy, context);
        if (!isSuccessfulPolicy(validated)) {
          continue;
        }

        for (const allowed of validated.policy.allow) {
          if (!result[allowed]) {
            result[allowed] = { reason: validated, allow: true };
          }
        }
        for (const denied of validated.policy.deny) {
          if (!result[denied] || result[denied].allow) {
            result[denied] = { reason: validated, allow: false };
          }
        }
      }
    }
    return result;
  }

  /**
   * Determines if it makes sense to evaluate a policy,
   * based on the permissions already granted and the permissions being requested.
   *
   * @param policy - Policy to investigate.
   * @param permissionMap - Maps of permissions that were already established.
   * @param permissions - Permissions being requested
   */
  protected isRelevantPolicy(policy: Policy, permissionMap: AcpPermissionMap, permissions?: string[]): boolean {
    const allow = policy.allow;
    const deny = policy.deny;
    if (permissions && !permissions.some((perm): boolean => allow.has(perm) || deny.has(perm))) {
      // Ignore policies that don't provide relevant information
      return false;
    }
    // In case an `allow` permission already has a result, we do not need to calculate it again.
    // A `deny` result can only be ignored if there already is proof that permission is not allowed,
    // as a `deny` trumps an `allow`.
    return [ ...allow ].some((perm): boolean => !permissionMap[perm]) ||
      [ ...deny ].some((perm): boolean => !permissionMap[perm] || permissionMap[perm].allow);
  };
}
