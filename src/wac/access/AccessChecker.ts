import { AsyncHandler } from 'asynchronous-handlers';
import type { Credentials } from '../../Credentials';
import type { WacAuthorization } from '../WacAuthorization';
import type { WacAuthValidation } from '../WacAuthValidation';

/**
 * Performs an authorization check against the given acl authorization.
 */
export abstract class AccessChecker extends AsyncHandler<AccessCheckerArgs, WacAuthValidation> {}

export interface AccessCheckerArgs {
  /**
   *  An ACL authorization objects.
   */
  auth: WacAuthorization;

  /**
   * Credentials of the entity that wants to use the resource.
   */
  credentials: Credentials;
}
