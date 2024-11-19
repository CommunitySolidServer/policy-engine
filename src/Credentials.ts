/**
 * Credentials of the agent that is requesting permissions.
 */
export interface Credentials {
  agent?: string;
  client?: string;
  issuer?: string;
  vc?: string[];
}
