import 'jest-rdf';
import * as crypto from 'node:crypto';
import { Parser, Store } from 'n3';
import type { AccessControlResource } from '../../../src/acp/Acp';
import { getAccessControlResources } from '../../../src/acp/AcpParseUtil';
import { AcpPolicyEngine } from '../../../src/acp/AcpPolicyEngine';
import type { AcpRepository } from '../../../src/acp/AcpRepository';
import { ACL } from '../../../src/Vocabularies';

// This allows us to spy on randomUUID
jest.mock<typeof import('node:crypto')>('node:crypto', (): any => (
  { __esModule: true, ...jest.requireActual('node:crypto') }));

jest
  .useFakeTimers()
  .setSystemTime(new Date('1988-03-09'));

describe('AcpPolicyEngine', (): void => {
  let uuidCounter: number;
  const uuidSpy = jest.spyOn(crypto, 'randomUUID');
  // eslint-disable-next-line no-plusplus
  uuidSpy.mockImplementation(((): string => `${uuidCounter++}`) as any);

  let acrs: AccessControlResource[];
  let repo: jest.Mocked<AcpRepository>;
  let engine: AcpPolicyEngine;

  beforeEach(async(): Promise<void> => {
    uuidCounter = 1;
    uuidSpy.mockClear();

    const data = new Store(new Parser({ format: 'Turtle', baseIRI: 'http://example.com/' }).parse(`
      @prefix acp: <http://www.w3.org/ns/solid/acp#>.
      @prefix acl: <http://www.w3.org/ns/auth/acl#>.
      @prefix ex: <http://example.com/>.
      
      ex:acr
        acp:resource <>;
        acp:accessControl ex:ac.
      
      ex:ac acp:apply ex:policy, ex:policy2.
      ex:policy
        acp:allow acl:Read, acl:Append;
        acp:deny acl:Write;
        acp:allOf ex:matcher.
      ex:matcher acp:agent ex:agent.
      
      ex:policy2
        acp:allow acl:Control;
        acp:allOf ex:matcher2.
      ex:matcher2 acp:agent ex:otherAgent.
    `));
    acrs = [ ...getAccessControlResources(data) ];

    repo = {
      // eslint-disable-next-line unused-imports/no-unused-vars
      getRelevantACRs: jest.fn(async function* (id: string): AsyncGenerator<AccessControlResource> {
        yield* acrs;
      }),
    };

    engine = new AcpPolicyEngine(repo);
  });

  it('returns the correct permissions.', async(): Promise<void> => {
    await expect(engine.getPermissions('http://example.com/', { agent: 'http://example.com/agent' }))
      .resolves.toEqual({
        [ACL.Read]: true,
        [ACL.Append]: true,
        [ACL.Write]: false,
      });
  });

  it('only looks for policies with relevant permissions.', async(): Promise<void> => {
    await expect(engine.getPermissions('http://example.com/', { agent: 'http://example.com/agent' }, [ ACL.Control ]))
      .resolves.toEqual({});
  });

  it('generates a valid report.', async(): Promise<void> => {
    const result = await engine.getPermissionsWithReport('http://example.com/', { agent: 'http://example.com/agent' });
    expect(result.permissions).toEqual({
      [ACL.Read]: true,
      [ACL.Append]: true,
      [ACL.Write]: false,
    });

    const expectedRdf = `
    @prefix acp: <http://www.w3.org/ns/solid/acp#>.
    @prefix acpr: <urn:report:acp:>.
    @prefix acl: <http://www.w3.org/ns/auth/acl#>.
    @prefix dc: <http://purl.org/dc/terms/>.
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
    @prefix report: <urn:report:default:>.
    
    <urn:uuid:2> a acpr:AcpReport;
        dc:created "1988-03-09T00:00:00.000Z"^^xsd:dateTime;
        acp:context <urn:uuid:1>;
        report:grant acl:Append, acl:Read;
        acpr:policyReport <urn:uuid:3>;
        report:deny acl:Write.
    <urn:uuid:1> a acp:Context;
        acp:target <http://example.com/>;
        acp:agent <http://example.com/agent>.
    <urn:uuid:3> a acpr:PolicyReport;
        acpr:policy <http://example.com/policy>;
        acpr:constraintReport <urn:uuid:4>.
    <urn:uuid:4> acpr:constraint acp:allOf;
        report:proof <urn:uuid:5>.
    <urn:uuid:5> acpr:matcher <http://example.com/matcher>;
        acpr:success true;
        acp:agent <http://example.com/agent>.`;

    const expectedQuads = new Parser().parse(expectedRdf);
    expect(result.quads).toBeRdfIsomorphic(expectedQuads);
  });
});
