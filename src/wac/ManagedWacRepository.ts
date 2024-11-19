import type { DatasetCore, NamedNode, Term } from '@rdfjs/types';
import { getLoggerFor } from 'global-logger-factory';
import { DataFactory, Store } from 'n3';
import type { AuthorizationManager } from '../AuthorizationManager';
import { ACL } from '../Vocabularies';
import type { WacAuthorization } from './WacAuthorization';
import type { WacRepository } from './WacRepository';

/**
 * ACL data and the identifier of the associated resource.
 */
export type AclEntry = { subjectId: string; data: DatasetCore };

/**
 * An implementation of {@link WacRepository} that uses an {@link AuthorizationManager} to find the relevant data.
 */
export class ManagedWacRepository implements WacRepository {
  protected readonly logger = getLoggerFor(this);

  public constructor(protected readonly manager: AuthorizationManager) {}

  public async* getRelevantAuthorizations(target: string): AsyncGenerator<WacAuthorization, void> {
    this.logger.debug(`Searching ACL data for ${target}`);
    const aclEntry = await this.getAclRecursive(target);
    yield* this.findRelevantAuthorizations(target, aclEntry);
  }

  /**
   * Finds the effective ACL resource and its contents for the given identifier,
   * following the steps defined in https://solidproject.org/TR/2021/wac-20210711#effective-acl-resource.
   *
   * @param identifier - Identifier for which we need the effective ACL resource.
   *
   * @returns The identifier of the effective ACL resource.
   */
  protected async getAclRecursive(identifier: string): Promise<AclEntry> {
    // Obtain the direct ACL document for the resource, if it exists
    this.logger.debug(`Trying to read the direct ACL data of ${identifier}`);
    const aclData = await this.manager.getAuthorizationData(identifier);
    if (aclData) {
      this.logger.info(`Found applicable ACL data for ${identifier}`);
      const data = Array.isArray(aclData) ? new Store(aclData) : aclData;
      return { subjectId: identifier, data };
    }
    this.logger.debug(`No direct ACL document found for ${identifier}`);

    // Find the applicable ACL document of the parent container
    this.logger.debug(`Traversing to the parent of ${identifier}`);
    const container = this.manager.getParent(identifier);
    if (!container) {
      this.logger.error(`No ACL document found for root container ${identifier}`);
      // https://solidproject.org/TR/2021/wac-20210711#acl-resource-representation
      // The root container MUST have an ACL resource with a representation.
      throw new Error('No ACL document found for root container');
    }
    return this.getAclRecursive(container);
  }

  /**
   * Find all relevant {@link WacAuthorization} for the given identifier in the given {@link AclEntry}.
   * The is based on the `acl:accessTo` and `acl:default` triples in every authorization of the entry.
   */
  protected* findRelevantAuthorizations(identifier: string, entry: AclEntry): Generator<WacAuthorization, void> {
    // If the effective ACL is the one that is linked to the resource, acl:accessTo needs to be used.
    // Otherwise, we check for acl:default.
    const directAcl = identifier === entry.subjectId;
    const accessQuads = entry.data.match(
      undefined,
      directAcl ? ACL.terms.accessTo : ACL.terms.default,
      DataFactory.namedNode(entry.subjectId),
    );

    for (const quad of accessQuads) {
      this.logger.debug(`Found authorization ${quad.subject.value}.`);
      yield {
        id: quad.subject as NamedNode,
        accessTo: this.parseAuthorizationField(entry.data, quad.subject, ACL.terms.accessTo),
        default: this.parseAuthorizationField(entry.data, quad.subject, ACL.terms.default),
        agent: this.parseAuthorizationField(entry.data, quad.subject, ACL.terms.agent),
        agentClass: this.parseAuthorizationField(entry.data, quad.subject, ACL.terms.agentClass),
        agentGroup: this.parseAuthorizationField(entry.data, quad.subject, ACL.terms.agentGroup),
        mode: this.parseAuthorizationField(entry.data, quad.subject, ACL.terms.mode),
      };
    }
  }

  protected parseAuthorizationField(data: DatasetCore, subject: Term, predicate: Term): Term[] {
    return [ ...data.match(subject, predicate) ].map((quad): Term => quad.object);
  }
}
