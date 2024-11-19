import { ACL, FOAF } from '../../Vocabularies';
import type { WacAuthValidation } from '../WacAuthValidation';
import type { AccessCheckerArgs } from './AccessChecker';
import { AccessChecker } from './AccessChecker';

/**
 * Checks access based on the agent class.
 */
export class AgentClassAccessChecker extends AccessChecker {
  public async handle({ auth, credentials: { agent }}: AccessCheckerArgs): Promise<WacAuthValidation> {
    const result: WacAuthValidation = { auth };
    // Check if unauthenticated agents have access
    if (auth.agentClass.some((term): boolean => term.equals(FOAF.terms.Agent))) {
      result.agentClass = { success: true, reason: FOAF.Agent };
    } else if (typeof agent === 'string' &&
      auth.agentClass.some((term): boolean => term.equals(ACL.terms.AuthenticatedAgent))) {
      // Check if the agent is authenticated and if authenticated agents have access
      result.agentClass = { success: true, reason: ACL.AuthenticatedAgent };
    }
    return result;
  }
}
