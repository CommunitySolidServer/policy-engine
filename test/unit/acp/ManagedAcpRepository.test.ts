import { Parser } from 'n3';
import type { AccessControlResource } from '../../../src/acp/Acp';
import { ManagedAcpRepository } from '../../../src/acp/ManagedAcpRepository';
import type { AuthorizationManager } from '../../../src/AuthorizationManager';
import { ACL } from '../../../src/Vocabularies';

describe('ManagedAcpRepository', (): void => {
  let manager: jest.Mocked<AuthorizationManager>;
  let repo: ManagedAcpRepository;

  beforeEach(async(): Promise<void> => {
    manager = {
      getParent: jest.fn(),
      getAuthorizationData: jest.fn(),
    };

    repo = new ManagedAcpRepository(manager);
  });

  it('returns nothing if there is no data.', async(): Promise<void> => {
    const acrs: AccessControlResource[] = [];
    for await (const acr of repo.getRelevantACRs('target')) {
      acrs.push(acr);
    }
    expect(acrs).toHaveLength(0);
  });

  it('returns valid ACRs.', async(): Promise<void> => {
    const acp = `
      @prefix acp: <http://www.w3.org/ns/solid/acp#>.
      @prefix acl: <http://www.w3.org/ns/auth/acl#>.
      <#acr>
          acp:resource <./>;
          acp:memberAccessControl [ acp:apply <#policy> ].
      <#policy>
        acp:allow acl:Write;
        acp:deny acl:Control;
        acp:noneOf <#matcher>.
      <#matcher> acp:agent <http://example.org/someone-else>.`;

    manager.getParent.mockReturnValueOnce('parent');
    manager.getAuthorizationData.mockResolvedValueOnce(new Parser({ baseIRI: 'http://example.com/.acr' }).parse(acp));

    const acrs: AccessControlResource[] = [];
    for await (const acr of repo.getRelevantACRs('target')) {
      acrs.push(acr);
    }
    expect(acrs).toHaveLength(1);
    expect(acrs[0].iri).toBe('http://example.com/.acr#acr');
    expect(acrs[0].resource).toHaveLength(1);
    expect(acrs[0].resource[0]).toBe('http://example.com/');
    expect(acrs[0].accessControl).toHaveLength(0);
    expect(acrs[0].memberAccessControl).toHaveLength(1);
    expect(acrs[0].memberAccessControl[0].policy).toHaveLength(1);
    expect(acrs[0].memberAccessControl[0].policy[0].iri).toBe('http://example.com/.acr#policy');
    expect(acrs[0].memberAccessControl[0].policy[0].allow.has(ACL.Write)).toBe(true);
    expect(acrs[0].memberAccessControl[0].policy[0].deny.has(ACL.Control)).toBe(true);
    expect(acrs[0].memberAccessControl[0].policy[0].noneOf).toHaveLength(1);
    expect(acrs[0].memberAccessControl[0].policy[0].noneOf[0].iri).toBe('http://example.com/.acr#matcher');
    expect(acrs[0].memberAccessControl[0].policy[0].noneOf[0].agent).toHaveLength(1);
    expect(acrs[0].memberAccessControl[0].policy[0].noneOf[0].agent[0]).toBe('http://example.org/someone-else');
  });
});
