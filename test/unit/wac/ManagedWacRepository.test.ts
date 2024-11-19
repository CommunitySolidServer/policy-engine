import 'jest-rdf';
import { DataFactory, Parser } from 'n3';
import type { AuthorizationManager } from '../../../src/AuthorizationManager';
import { ACL, FOAF } from '../../../src/Vocabularies';
import { ManagedWacRepository } from '../../../src/wac/ManagedWacRepository';
import type { WacAuthorization } from '../../../src/wac/WacAuthorization';

describe('ManagedWacRepository', (): void => {
  let manager: jest.Mocked<AuthorizationManager>;
  let repo: ManagedWacRepository;

  beforeEach(async(): Promise<void> => {
    manager = {
      getParent: jest.fn(),
      getAuthorizationData: jest.fn(),
    };

    repo = new ManagedWacRepository(manager);
  });

  it('throws an error if no root ACL is found.', async(): Promise<void> => {
    await expect(repo.getRelevantAuthorizations('http://example.com/foo').next())
      .rejects.toThrow('No ACL document found for root container');
  });

  it('returns a valid authorization.', async(): Promise<void> => {
    const acl = `
      @prefix acl: <http://www.w3.org/ns/auth/acl#>.
      @prefix foaf: <http://xmlns.com/foaf/0.1/>.
      <#foo>
          a acl:Authorization;
          acl:agentClass foaf:Agent;
          acl:default <./>;
          acl:mode acl:Write.
      `;
    manager.getParent.mockReturnValue('http://example.com/');
    manager.getAuthorizationData.mockResolvedValueOnce(undefined);
    manager.getAuthorizationData.mockResolvedValueOnce(new Parser({ baseIRI: 'http://example.com/.acl' }).parse(acl));

    const result: WacAuthorization[] = [];
    for await (const auth of repo.getRelevantAuthorizations('http://example.com/foo')) {
      result.push(auth);
    }
    expect(result).toHaveLength(1);
    expect(result[0].id).toEqualRdfTerm(DataFactory.namedNode('http://example.com/.acl#foo'));
    expect(result[0].accessTo).toHaveLength(0);
    expect(result[0].default).toHaveLength(1);
    expect(result[0].default[0]).toEqualRdfTerm(DataFactory.namedNode('http://example.com/'));
    expect(result[0].agent).toHaveLength(0);
    expect(result[0].agentClass).toHaveLength(1);
    expect(result[0].agentClass[0]).toEqualRdfTerm(FOAF.terms.Agent);
    expect(result[0].agentGroup).toHaveLength(0);
    expect(result[0].mode).toHaveLength(1);
    expect(result[0].mode[0]).toEqualRdfTerm(ACL.terms.Write);
  });
});
