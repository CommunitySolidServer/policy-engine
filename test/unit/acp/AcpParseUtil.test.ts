import { DataFactory as DF, Parser, Store } from 'n3';
import type { AccessControlResource, Policy } from '../../../src/acp/Acp';
import {
  getAccessControl,
  getAccessControlResource,
  getAccessControlResources,
  getEffectivePolicies,
  getMatcher,
  getPolicy,
} from '../../../src/acp/AcpParseUtil';
import { ACL, ACP } from '../../../src/Vocabularies';

describe('AcpParseUtil', (): void => {
  const baseUrl = 'http://example.com/';
  const data = new Store(new Parser({ format: 'Turtle', baseIRI: baseUrl }).parse(`
  @prefix acp: <http://www.w3.org/ns/solid/acp#>.
  @prefix acl: <http://www.w3.org/ns/auth/acl#>.
  @prefix ex: <http://example.com/>.
  
  ex:acr
    acp:resource <./foo>;
    acp:accessControl ex:ac;
    acp:memberAccessControl ex:ac.
  ex:ac acp:apply ex:policy.
  ex:policy
    acp:allow acl:Read, acl:Append;
    acp:deny acl:Write;
    acp:allOf ex:matcher;
    acp:anyOf ex:matcher;
    acp:noneOf ex:matcher.
  ex:matcher acp:agent acp:PublicAgent, ex:agent;
             acp:client ex:client;
             acp:issuer ex:issuer;
             acp:vc ex:vc.
  `));

  describe('#getMatcher', (): void => {
    it('returns the relevant matcher.', async(): Promise<void> => {
      expect(getMatcher(data, DF.namedNode(`${baseUrl}matcher`))).toEqual({
        iri: `${baseUrl}matcher`,
        agent: [ `${ACP.namespace}PublicAgent`, `${baseUrl}agent` ],
        client: [ `${baseUrl}client` ],
        issuer: [ `${baseUrl}issuer` ],
        vc: [ `${baseUrl}vc` ],
      });
    });
    it('returns an empty matcher if no data is found.', async(): Promise<void> => {
      expect(getMatcher(data, DF.namedNode(`${baseUrl}unknown`))).toEqual({
        iri: `${baseUrl}unknown`,
        agent: [],
        client: [],
        issuer: [],
        vc: [],
      });
    });
  });

  describe('#getPolicy', (): void => {
    it('returns the relevant policy.', async(): Promise<void> => {
      expect(getPolicy(data, DF.namedNode(`${baseUrl}policy`))).toEqual({
        iri: `${baseUrl}policy`,
        allow: new Set([ ACL.Read, ACL.Append ]),
        deny: new Set([ ACL.Write ]),
        allOf: [ expect.objectContaining({ iri: `${baseUrl}matcher` }) ],
        anyOf: [ expect.objectContaining({ iri: `${baseUrl}matcher` }) ],
        noneOf: [ expect.objectContaining({ iri: `${baseUrl}matcher` }) ],
      });
    });
    it('returns an empty policy if no data is found.', async(): Promise<void> => {
      expect(getPolicy(data, DF.namedNode(`${baseUrl}unknown`))).toEqual({
        iri: `${baseUrl}unknown`,
        allow: new Set(),
        deny: new Set(),
        allOf: [],
        anyOf: [],
        noneOf: [],
      });
    });
  });

  describe('#getAccessControl', (): void => {
    it('returns the relevant access control.', async(): Promise<void> => {
      expect(getAccessControl(data, DF.namedNode(`${baseUrl}ac`))).toEqual({
        iri: `${baseUrl}ac`,
        policy: [ expect.objectContaining({ iri: `${baseUrl}policy` }) ],
      });
    });
    it('returns an empty access control if no data is found.', async(): Promise<void> => {
      expect(getAccessControl(data, DF.namedNode(`${baseUrl}unknown`))).toEqual({
        iri: `${baseUrl}unknown`,
        policy: [],
      });
    });
  });

  describe('#getAccessControlResource', (): void => {
    it('returns the relevant access control resource.', async(): Promise<void> => {
      expect(getAccessControlResource(data, DF.namedNode(`${baseUrl}acr`))).toEqual({
        iri: `${baseUrl}acr`,
        resource: [ `${baseUrl}foo` ],
        accessControl: [ expect.objectContaining({ iri: `${baseUrl}ac` }) ],
        memberAccessControl: [ expect.objectContaining({ iri: `${baseUrl}ac` }) ],
      });
    });
    it('returns an empty access control resource if no data is found.', async(): Promise<void> => {
      expect(getAccessControlResource(data, DF.namedNode(`${baseUrl}unknown`))).toEqual({
        iri: `${baseUrl}unknown`,
        resource: [],
        accessControl: [],
        memberAccessControl: [],
      });
    });
  });

  describe('#getAccessControlledResources', (): void => {
    it('returns all access controlled resources found in the dataset.', async(): Promise<void> => {
      expect([ ...getAccessControlResources(data) ]).toEqual([ expect.objectContaining({
        iri: `${baseUrl}acr`,
        resource: [ `${baseUrl}foo` ],
      }) ]);
    });
  });

  describe('#getEffectivePolicies', (): void => {
    const access1: Policy = {
      iri: 'access1',
      allow: new Set(),
      deny: new Set(),
      allOf: [],
      anyOf: [],
      noneOf: [],
    };
    const access2: Policy = { ...access1, iri: 'access2' };
    const member1: Policy = { ...access1, iri: 'member1' };
    const member2: Policy = { ...access1, iri: 'member2' };

    const acr: AccessControlResource = {
      iri: 'acr',
      resource: [ 'http://example.com/foo/' ],
      accessControl: [{ iri: 'ac', policy: [ access1, access2 ]}],
      memberAccessControl: [{ iri: 'ac', policy: [ member1, member2 ]}],
    };

    it('returns the access control policies if the target matches the IRI.', async(): Promise<void> => {
      expect([ ...getEffectivePolicies(acr.resource[0], acr) ]).toEqual([ access1, access2 ]);
    });

    it('returns the member access control policies if the target does not match the IRI.', async(): Promise<void> => {
      expect([ ...getEffectivePolicies('http://example.com/foo/bar', acr) ]).toEqual([ member1, member2 ]);
    });
  });
});
