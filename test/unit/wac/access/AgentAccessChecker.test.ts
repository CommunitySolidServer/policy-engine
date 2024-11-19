import { DataFactory } from 'n3';
import type { AccessCheckerArgs } from '../../../../src/wac/access/AccessChecker';
import { AgentAccessChecker } from '../../../../src/wac/access/AgentAccessChecker';
import type { WacAuthorization } from '../../../../src/wac/WacAuthorization';

describe('AgentAccessChecker', (): void => {
  const webId = 'http://test.com/alice/profile/card#me';
  const checker = new AgentAccessChecker();
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

  it('returns true if a match is found for the given WebID.', async(): Promise<void> => {
    auth.agent.push(DataFactory.namedNode(webId));
    const input: AccessCheckerArgs = { auth, credentials: { agent: webId }};
    await expect(checker.handle(input)).resolves.toEqual({
      agent: { reason: 'http://test.com/alice/profile/card#me', success: true },
      auth,
    });
  });

  it('returns false if no match is found.', async(): Promise<void> => {
    auth.agent.push(DataFactory.namedNode('http://test.com/bob'));
    const input: AccessCheckerArgs = { auth, credentials: { agent: webId }};
    await expect(checker.handle(input)).resolves.toEqual({ auth });
  });

  it('returns false if the credentials contain no WebID.', async(): Promise<void> => {
    const input: AccessCheckerArgs = { auth, credentials: {}};
    await expect(checker.handle(input)).resolves.toEqual({ auth });
  });
});
