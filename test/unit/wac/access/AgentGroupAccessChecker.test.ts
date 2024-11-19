import type { DatasetCore } from '@rdfjs/types';
import { DataFactory, Store } from 'n3';
import rdfFetch from '@rdfjs/fetch';
import { ACL, VCARD } from '../../../../src/Vocabularies';
import type { AccessCheckerArgs } from '../../../../src/wac/access/AccessChecker';
import { AgentGroupAccessChecker } from '../../../../src/wac/access/AgentGroupAccessChecker';
import type { WacAuthorization } from '../../../../src/wac/WacAuthorization';

jest.mock('@rdfjs/fetch');

describe('AgentGroupAccessChecker', (): void => {
  const webId = 'http://test.com/alice/profile/card#me';
  const groupId = 'http://test.com/group';
  const acl = new Store();
  acl.addQuad(DataFactory.namedNode('groupMatch'), ACL.terms.agentGroup, DataFactory.namedNode(groupId));
  acl.addQuad(DataFactory.namedNode('noMatch'), ACL.terms.agentGroup, DataFactory.namedNode('badGroup'));
  const fetchMock = jest.mocked(rdfFetch);
  let dataset: DatasetCore;
  let checker: AgentGroupAccessChecker;
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
    const groupQuads = [
      DataFactory.quad(DataFactory.namedNode(groupId), VCARD.terms.hasMember, DataFactory.namedNode(webId)),
    ];
    dataset = new Store(groupQuads);
    fetchMock.mockResolvedValue({ dataset: async(): Promise<DatasetCore> => dataset } as any);
    fetchMock.mockClear();

    checker = new AgentGroupAccessChecker();
  });

  it('can handle all requests.', async(): Promise<void> => {
    await expect(checker.canHandle(null as any)).resolves.toBeUndefined();
  });

  it('returns true if the WebID is a valid group member.', async(): Promise<void> => {
    auth.agentGroup.push(DataFactory.namedNode(groupId));
    const input: AccessCheckerArgs = { auth, credentials: { agent: webId }};
    await expect(checker.handle(input)).resolves.toEqual({
      agentGroup: { reason: 'http://test.com/group', success: true },
      auth,
    });
  });

  it('returns false if the WebID is not a valid group member.', async(): Promise<void> => {
    auth.agentGroup.push(DataFactory.namedNode('badGroup'));
    const input: AccessCheckerArgs = { auth, credentials: { agent: webId }};
    await expect(checker.handle(input)).resolves.toEqual({ auth });
  });

  it('returns false if there are no WebID credentials.', async(): Promise<void> => {
    auth.agentGroup.push(DataFactory.namedNode(groupId));
    const input: AccessCheckerArgs = { auth, credentials: {}};
    await expect(checker.handle(input)).resolves.toEqual({ auth });
  });
});
