import 'jest-rdf';
import * as crypto from 'node:crypto';
import type { Quad } from '@rdfjs/types';
import { Parser } from 'n3';
import { AclPermissionsEngine } from '../../src/AclPermissionsEngine';
import { AcpPolicyEngine } from '../../src/acp/AcpPolicyEngine';
import { ManagedAcpRepository } from '../../src/acp/ManagedAcpRepository';
import type { AuthorizationManager } from '../../src/AuthorizationManager';
import type { Credentials } from '../../src/Credentials';
import { AgentAccessChecker } from '../../src/wac/access/AgentAccessChecker';
import { AgentClassAccessChecker } from '../../src/wac/access/AgentClassAccessChecker';
import { AgentGroupAccessChecker } from '../../src/wac/access/AgentGroupAccessChecker';
import { UnionAccessChecker } from '../../src/wac/access/UnionAccessChecker';
import { ManagedWacRepository } from '../../src/wac/ManagedWacRepository';
import { WacPolicyEngine } from '../../src/wac/WacPolicyEngine';

const credentials: Credentials = {
  agent: 'http://example.com/alice',
  client: 'http://localhost:3000/client',
};

const acpFoo = `
@prefix acp: <http://www.w3.org/ns/solid/acp#>.
@prefix acl: <http://www.w3.org/ns/auth/acl#>.
<#acr>
    acp:resource <./foo>;
    acp:accessControl [ acp:apply <#policy>, <#policy2> ].
<#policy>
  acp:allow acl:Read, acl:Control;
  acp:allOf <#matcher>.
<#matcher> acp:agent acp:PublicAgent.
  
<#policy2>
  acp:allow acl:Write;
  acp:allOf <#matcher2>.`;

const acpRoot = `
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

const aclRoot = `
@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.
<#public>
    a acl:Authorization;
    acl:agentClass foaf:Agent;
    acl:accessTo <./>;
    acl:mode acl:Read.

<#owner>
    a acl:Authorization;
    acl:agent <${credentials.agent}>;
    acl:accessTo <./>;
    acl:default <./>;
    acl:mode
        acl:Read, acl:Write, acl:Control.
`;

const aclFoo = `
@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.
<#foo>
    a acl:Authorization;
    acl:agentClass foaf:Agent;
    acl:accessTo <./foo>;
    acl:mode acl:Write.
`;

const root = 'http://example.org/';
const foo = 'http://example.org/foo';

const acpManager: AuthorizationManager = {
  getParent: (id: string): string | undefined => {
    if (id === foo) {
      return root;
    }
  },
  getAuthorizationData: async(id: string): Promise<Quad[]> => {
    const acp = id === foo ? acpFoo : acpRoot;
    const parser = new Parser({ baseIRI: `${id}.acr` });
    return parser.parse(acp);
  },
};

const wacManager: AuthorizationManager = {
  getParent: acpManager.getParent,
  getAuthorizationData: async(id: string): Promise<Quad[]> => {
    const parser = new Parser({ baseIRI: `${id}.acl` });
    return parser.parse(id === root ? aclRoot : aclFoo);
  },
};

const acpPolicyEngine = new AcpPolicyEngine(new ManagedAcpRepository(acpManager));

const accessChecker = new UnionAccessChecker([
  new AgentAccessChecker(),
  new AgentClassAccessChecker(),
  new AgentGroupAccessChecker(),
]);
const wacPolicyEngine = new WacPolicyEngine(accessChecker, new ManagedWacRepository(wacManager));

const comboEngine = new AclPermissionsEngine(wacPolicyEngine, wacManager);

// This allows us to spy on randomUUID
jest.mock<typeof import('node:crypto')>('node:crypto', (): any => (
  { __esModule: true, ...jest.requireActual('node:crypto') }));

jest
  .useFakeTimers()
  .setSystemTime(new Date('1988-03-09'));

describe('PolicyEngine', (): void => {
  let uuidCounter: number;
  const uuidSpy = jest.spyOn(crypto, 'randomUUID');
  // eslint-disable-next-line no-plusplus
  uuidSpy.mockImplementation(((): string => `${uuidCounter++}`) as any);

  beforeEach(async(): Promise<void> => {
    uuidCounter = 1;
    uuidSpy.mockClear();
  });

  it('should generate an ACP report.', async(): Promise<void> => {
    const expectedRdf = `
    @prefix acp: <http://www.w3.org/ns/solid/acp#>.
    @prefix acpr: <urn:report:acp:>.
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
    @prefix report: <urn:report:default:>.
    
    <urn:uuid:2> a acpr:AcpReport;
        <http://purl.org/dc/terms/created> "1988-03-09T00:00:00.000Z"^^xsd:dateTime;
        acp:context <urn:uuid:1>;
        report:grant acl:Read, acl:Write;
        acpr:policyReport <urn:uuid:3>, <urn:uuid:6>;
        report:deny acl:Control.
    <urn:uuid:1> a acp:Context;
        acp:agent <http://example.com/alice>;
        acp:target <http://example.org/foo>;
        acp:client <http://localhost:3000/client>.
    <urn:uuid:3> a acpr:PolicyReport;
        acpr:policy <http://example.org/foo.acr#policy>;
        acpr:constraintReport <urn:uuid:4>.
    <urn:uuid:4> acpr:constraint acp:allOf;
        report:proof <urn:uuid:5>.
    <urn:uuid:5> acpr:matcher <http://example.org/foo.acr#matcher>;
        acpr:success true;
        acp:agent acp:PublicAgent.
    <urn:uuid:6> a acpr:PolicyReport;
        acpr:policy <http://example.org/.acr#policy>;
        acpr:constraintReport <urn:uuid:7>.
    <urn:uuid:7> acpr:constraint acp:noneOf;
        report:proof <urn:uuid:8>.
    <urn:uuid:8> acpr:matcher <http://example.org/.acr#matcher>;
        acpr:success false;
        acp:agent false.`;

    const expectedQuads = new Parser().parse(expectedRdf);

    const acpReport = await acpPolicyEngine.getPermissionsWithReport(foo, credentials);
    expect(acpReport.permissions).toEqual({
      'http://www.w3.org/ns/auth/acl#Read': true,
      'http://www.w3.org/ns/auth/acl#Write': true,
      'http://www.w3.org/ns/auth/acl#Control': false,
    });
    expect(acpReport.quads).toBeRdfIsomorphic(expectedQuads);
  });

  it('should generate a WAC report.', async(): Promise<void> => {
    const expectedRdf = `
    @prefix wacr: <urn:report:wac:>.
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
    
    <urn:uuid:1> a wacr:WacAclReport;
        <http://purl.org/dc/terms/created> "1988-03-09T00:00:00.000Z"^^xsd:dateTime;
        acl:agent <http://example.com/alice>;
        <urn:report:default:target> <http://example.org/>;
        acl:mode acl:Read, acl:Write, acl:Control;
        wacr:authReport <urn:uuid:2>.
    <urn:uuid:2> a wacr:WacAuthReport;
        wacr:authorization <http://example.org/.acl#owner>;
        wacr:subjectReport <urn:uuid:3>.
    <urn:uuid:3> acl:agent <http://example.com/alice>.`;

    const expectedQuads = new Parser().parse(expectedRdf);

    const report = await wacPolicyEngine.getPermissionsWithReport(root, credentials);
    expect(report.quads).toBeRdfIsomorphic(expectedQuads);
  });

  it('can combine multiple reports when determining non-acl permissions.', async(): Promise<void> => {
    const expectedRdf = `
    @prefix wacr: <urn:report:wac:>.
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
    @prefix report: <urn:report:default:>.
    
    <urn:uuid:7> a report:Report;
        report:target <http://example.org/foo>;
        report:grant acl:Write,
                     acl:Append,
                     <urn:report:permissions:Append>,
                     <urn:report:permissions:Create>,
                     <urn:report:permissions:Delete>,
                     <urn:report:permissions:Modify>;
        report:proof <urn:uuid:1>, <urn:uuid:4>.
    <urn:uuid:1> a wacr:WacAclReport;
        <http://purl.org/dc/terms/created> "1988-03-09T00:00:00.000Z"^^xsd:dateTime;
        report:target <http://example.org/foo>;
        acl:agent <http://example.com/alice>;
        acl:mode acl:Write;
        wacr:authReport <urn:uuid:2>.
    <urn:uuid:2> a wacr:WacAuthReport;
        wacr:authorization <http://example.org/foo.acl#foo>;
        wacr:subjectReport <urn:uuid:3>.
    <urn:uuid:3> acl:agentClass <http://xmlns.com/foaf/0.1/Agent>.
    <urn:uuid:4> a wacr:WacAclReport;
        <http://purl.org/dc/terms/created> "1988-03-09T00:00:00.000Z"^^xsd:dateTime;
        report:target <http://example.org/>;
        acl:agent <http://example.com/alice>;
        acl:mode acl:Write, acl:Read, acl:Control;
        wacr:authReport <urn:uuid:5>.
    <urn:uuid:5> a wacr:WacAuthReport;
        wacr:authorization <http://example.org/.acl#owner>;
        wacr:subjectReport <urn:uuid:6>.
    <urn:uuid:6> acl:agent <http://example.com/alice>.`;

    const expectedQuads = new Parser().parse(expectedRdf);

    const report = await comboEngine.getPermissionsWithReport(foo, credentials);
    expect(report.quads).toBeRdfIsomorphic(expectedQuads);
  });
});
