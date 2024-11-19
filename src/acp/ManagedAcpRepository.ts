import type { DatasetCore } from '@rdfjs/types';
import { Store } from 'n3';
import { getLoggerFor } from 'global-logger-factory';
import type { AuthorizationManager } from '../AuthorizationManager';
import type { AccessControlResource } from './Acp';
import { getAccessControlResources } from './AcpParseUtil';
import type { AcpRepository } from './AcpRepository';

/**
 * An implementation of {@link AcpRepository} that uses an {@link AuthorizationManager} to find the relevant data.
 */
export class ManagedAcpRepository implements AcpRepository {
  protected readonly logger = getLoggerFor(this);

  public constructor(protected readonly manager: AuthorizationManager) {}

  public async* getRelevantACRs(target: string): AsyncGenerator<AccessControlResource, void> {
    for (const identifier of this.getAncestorIdentifiers(target)) {
      yield* getAccessControlResources(await this.readAcrData(identifier));
    }
  }

  /**
   * Returns the given identifier and all its ancestors.
   * These are all the identifiers that are relevant for determining the effective policies.
   */
  protected* getAncestorIdentifiers(identifier: string): Generator<string, void> {
    let ancestor: string | undefined = identifier;
    while (ancestor) {
      yield ancestor;
      ancestor = this.manager.getParent(ancestor);
    }
  }

  /**
   * Returns the data found in the ACR corresponding to the given identifier.
   */
  protected async readAcrData(identifier: string): Promise<DatasetCore> {
    // Obtain the direct ACR document for the resource, if it exists
    this.logger.debug(`Reading ACR document of ${identifier}`);
    const data = await this.manager.getAuthorizationData(identifier);
    if (data) {
      this.logger.info(`Found applicable ACR data for ${identifier}`);
      return Array.isArray(data) ? new Store(data) : data;
    }
    this.logger.debug(`No direct ACR document found for ${identifier}`);
    return new Store();
  }
}
