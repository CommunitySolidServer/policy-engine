import type { WacAuthValidation } from '../WacAuthValidation';
import type { AccessCheckerArgs } from './AccessChecker';
import { AccessChecker } from './AccessChecker';

/**
 * Checks if the given WebID has been given access.
 */
export class AgentAccessChecker extends AccessChecker {
  public async handle({ auth, credentials: { agent }}: AccessCheckerArgs): Promise<WacAuthValidation> {
    const result: WacAuthValidation = { auth };
    if (typeof agent === 'string' && auth.agent.some((term): boolean => term.value === agent)) {
      result.agent = { success: true, reason: agent };
    }
    return result;
  }
}
