import type { AsyncHandlerOutput } from 'asynchronous-handlers';
import { UnionHandler } from 'asynchronous-handlers';

import type { WacAuthValidation } from '../WacAuthValidation';
import type { AccessChecker } from './AccessChecker';

/**
 * Combines the result of multiple {@link AccessChecker}s.
 */
export class UnionAccessChecker extends UnionHandler<AccessChecker> {
  public constructor(handlers: AccessChecker[]) {
    super(handlers);
  }

  protected async combine(results: AsyncHandlerOutput<AccessChecker>[]): Promise<WacAuthValidation> {
    const result = results[0];
    for (let i = 1; i < results.length; i++) {
      for (const key of Object.keys(results[i]) as (keyof WacAuthValidation)[]) {
        if (key === 'auth' || result[key]) {
          continue;
        }
        result[key] = results[i][key];
      }
    }
    return result;
  }
}
