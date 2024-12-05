import { randomUUID } from 'node:crypto';
import { getLoggerFor } from 'global-logger-factory';
import type { Quad } from '@rdfjs/types';
import { DataFactory as DF } from 'n3';
import type { AuthorizationManager } from './AuthorizationManager';
import type { Credentials } from './Credentials';
import type { PermissionMap, PermissionReport, PolicyEngine } from './PolicyEngine';
import { ACL, PERMISSIONS, RDF, REPORT } from './Vocabularies';

export const ACL_TRANSLATE_MAP: Record<string, { target: string; parent?: string }> = {
  [PERMISSIONS.Append]: { target: ACL.Append },
  [PERMISSIONS.Create]: { target: ACL.Append, parent: ACL.Append },
  [PERMISSIONS.Delete]: { target: ACL.Write, parent: ACL.Write },
  [PERMISSIONS.Modify]: { target: ACL.Write },
  [PERMISSIONS.Read]: { target: ACL.Read },
};

/**
 * A {@link PolicyEngine} that converts ACL permissions to and from a general format.
 * It takes into account the extra checks that are necessary on parent containers
 * when determining Create and Delete permissions.
 */
export class AclPermissionsEngine implements PolicyEngine {
  protected readonly logger = getLoggerFor(this);

  public constructor(
    protected readonly engine: PolicyEngine,
    protected readonly manager: AuthorizationManager,
  ) {}

  public async getPermissions(target: string, credentials: Credentials, permissions?: string[]):
  Promise<PermissionMap> {
    const input = this.toAclPermissions(permissions);

    const targetResult = await this.engine.getPermissions(target, credentials, input.permissions);
    let parentResult: PermissionMap = {};
    // Only check parent permissions if they might be required
    if (!input.parentPermissions || input.parentPermissions.length > 0) {
      const parent = this.manager.getParent(target);
      if (parent) {
        parentResult = await this.engine.getPermissions(parent, credentials, input.parentPermissions);
      }
    }

    return this.fromAclPermissions(targetResult, parentResult);
  }

  public async getPermissionsWithReport(target: string, credentials: Credentials, permissions?: string[]):
  Promise<PermissionReport> {
    const input = this.toAclPermissions(permissions);

    const targetResult = await this.engine.getPermissionsWithReport(target, credentials, input.permissions);
    let parentResult: PermissionReport | undefined;
    // Only check parent permissions if they might be required
    if (!input.parentPermissions || input.parentPermissions.length > 0) {
      const parent = this.manager.getParent(target);
      if (parent) {
        parentResult = await this.engine.getPermissionsWithReport(parent, credentials, input.parentPermissions);
      }
    }

    const resultPermissions = this.fromAclPermissions(targetResult.permissions, parentResult?.permissions ?? {});
    const reportQuads: Quad[] = [];
    const id = DF.namedNode(`urn:uuid:${randomUUID()}`);
    reportQuads.push(DF.quad(id, RDF.terms.type, REPORT.terms.Report));
    reportQuads.push(DF.quad(id, REPORT.terms.target, DF.namedNode(target)));
    for (const [ perm, allowed ] of Object.entries(resultPermissions)) {
      reportQuads.push(DF.quad(id, REPORT.terms[allowed ? 'grant' : 'deny'], DF.namedNode(perm)));
    }

    reportQuads.push(DF.quad(id, REPORT.terms.proof, targetResult.id));
    reportQuads.push(...targetResult.quads);
    if (parentResult && Object.keys(parentResult.permissions).length > 0) {
      reportQuads.push(DF.quad(id, REPORT.terms.proof, parentResult.id));
      reportQuads.push(...parentResult.quads);
    }
    return {
      id,
      quads: reportQuads,
      permissions: resultPermissions,
    };
  }

  /**
   * Converts the given general permissions to ACL permissions,
   * indicating which are necessary on the target and which on the parent,
   * to have equivalent coverage.
   */
  protected toAclPermissions(permissions?: string[]): { permissions?: string[]; parentPermissions?: string[] } {
    if (typeof permissions === 'undefined') {
      return {};
    }
    const result: { permissions: string[]; parentPermissions: string[] } = { permissions: [], parentPermissions: []};
    for (const permission of permissions) {
      const aclTranslation = ACL_TRANSLATE_MAP[permission];
      if (aclTranslation) {
        result.permissions.push(aclTranslation.target);
        if (aclTranslation.parent) {
          result.parentPermissions.push(aclTranslation.parent);
        }
      }
      // Keep non-ACL permissions in case there is an ACL/ACR with custom permissions
      result.permissions.push(permission);
    }

    // If append permissions are requested we also need to check write as that implies append
    if (result.permissions.includes(ACL.Append) && !result.permissions.includes(ACL.Write)) {
      result.permissions.push(ACL.Write);
    }
    if (result.parentPermissions.includes(ACL.Append) && !result.parentPermissions.includes(ACL.Write)) {
      result.parentPermissions.push(ACL.Write);
    }

    return result;
  }

  /**
   * Converts the given ACL permissions, on the target and its parent container,
   * to general permissions.
   */
  protected fromAclPermissions(targetPermissions: PermissionMap, parentPermissions: PermissionMap): PermissionMap {
    if (targetPermissions[ACL.Write]) {
      targetPermissions[ACL.Append] = true;
    }
    if (parentPermissions[ACL.Write]) {
      parentPermissions[ACL.Append] = true;
    }
    const result: PermissionMap = { ...targetPermissions };
    for (const [ perm, aclPerm ] of Object.entries(ACL_TRANSLATE_MAP)) {
      const targetAllowed = result[aclPerm.target];
      const parentAllowed = aclPerm.parent ? parentPermissions[aclPerm.parent] : true;
      if (typeof targetAllowed !== 'undefined' && typeof parentAllowed !== 'undefined') {
        this.logger.debug(
          `Converting permission ${aclPerm.target} and parent permission ${aclPerm.parent} into ${perm}.`,
        );
        result[perm] = targetAllowed && parentAllowed;
      }
    }
    return result;
  }
}
