import type { DatasetCore, Term } from '@rdfjs/types';
import { DataFactory } from 'n3';
import rdfFetch from '@rdfjs/fetch';
import { VCARD } from '../../Vocabularies';
import type { WacAuthValidation } from '../WacAuthValidation';
import type { AccessCheckerArgs } from './AccessChecker';
import { AccessChecker } from './AccessChecker';

/**
 * Checks if the given WebID belongs to a group that has access.
 * Implements the behaviour of groups from the WAC specification.
 */
export class AgentGroupAccessChecker extends AccessChecker {
  public constructor() {
    super();
  }

  public async handle({ auth, credentials: { agent }}: AccessCheckerArgs): Promise<WacAuthValidation> {
    const result: WacAuthValidation = { auth };
    if (typeof agent === 'string') {
      try {
        // Return success if at least one group contains the WebID
        const reason = await Promise.any(auth.agentGroup.map(async(group: Term): Promise<string | undefined> => {
          if (await this.isMemberOfGroup(agent, group)) {
            return group.value;
          }
        }));
        if (reason) {
          result.agentGroup = { success: true, reason };
        }
      } catch {}
    }
    return result;
  }

  /**
   * Checks if the given agent is member of a given vCard group.
   *
   * @param webId - WebID of the agent that needs access.
   * @param group - URL of the vCard group that needs to be checked.
   *
   * @returns If the agent is member of the given vCard group.
   */
  private async isMemberOfGroup(webId: string, group: Term): Promise<boolean> {
    const groupDocument = /^[^#]*/u.exec(group.value)![0];

    // Fetch the required vCard group file
    const response = await rdfFetch<DatasetCore>(groupDocument);
    const dataset = await response.dataset();
    return dataset.match(group, VCARD.terms.hasMember, DataFactory.namedNode(webId)).size > 0;
  }
}
