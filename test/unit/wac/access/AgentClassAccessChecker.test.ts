import { DataFactory } from 'n3';
import { ACL, FOAF } from '../../../../src/Vocabularies';
import type { AccessCheckerArgs } from '../../../../src/wac/access/AccessChecker';
import { AgentClassAccessChecker } from '../../../../src/wac/access/AgentClassAccessChecker';
import type { WacAuthorization } from '../../../../src/wac/WacAuthorization';

describe('AgentClassAccessChecker', (): void => {
  const webId = 'http://test.com/alice/profile/card#me';
  const checker = new AgentClassAccessChecker();
  let auth: WacAuthorization;

  beforeEach(async(): Promise<void> => {
    auth = {
      id: DataFactory.namedNode('id'),
      agent: [],
      mode: [],
      accessTo: [],
      agentClass: [],
      default: [],
      agentGroup: [],
    };
  });

  it('can handle all requests.', async(): Promise<void> => {
    await expect(checker.canHandle(null as any)).resolves.toBeUndefined();
  });

  it('returns true if the rule contains foaf:agent as supported class.', async(): Promise<void> => {
    auth.agentClass.push(FOAF.terms.Agent);
    const input: AccessCheckerArgs = { auth, credentials: {}};
    await expect(checker.handle(input)).resolves.toEqual({
      agentClass: { reason: FOAF.Agent, success: true },
      auth,
    });
  });

  it('returns true for authenticated users with an acl:AuthenticatedAgent rule.', async(): Promise<void> => {
    auth.agentClass.push(ACL.terms.AuthenticatedAgent);
    const input: AccessCheckerArgs = { auth, credentials: { agent: webId }};
    await expect(checker.handle(input)).resolves.toEqual({
      agentClass: { reason: ACL.AuthenticatedAgent, success: true },
      auth,
    });
  });

  it('returns false for unauthenticated users with an acl:AuthenticatedAgent rule.', async(): Promise<void> => {
    auth.agentClass.push(ACL.terms.AuthenticatedAgent);
    const input: AccessCheckerArgs = { auth, credentials: {}};
    await expect(checker.handle(input)).resolves.toEqual({ auth });
  });

  it('returns false if no class rule is found.', async(): Promise<void> => {
    const input: AccessCheckerArgs = { auth, credentials: {}};
    await expect(checker.handle(input)).resolves.toEqual({ auth });
  });
});
