import type { NamedNode, Term } from '@rdfjs/types';

/**
 * Contents of a WAC authorization object.
 */
export interface WacAuthorization {
  id: NamedNode;
  accessTo: Term[];
  default: Term[];
  agent: Term[];
  agentClass: Term[];
  agentGroup: Term[];
  mode: Term[];
}
