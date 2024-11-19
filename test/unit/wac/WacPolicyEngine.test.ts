import 'jest-rdf';
import * as crypto from 'node:crypto';
import { DataFactory, Parser } from 'n3';
import { ACL } from '../../../src/Vocabularies';
import type { AccessChecker } from '../../../src/wac/access/AccessChecker';
import type { WacAuthorization } from '../../../src/wac/WacAuthorization';
import { WacPolicyEngine } from '../../../src/wac/WacPolicyEngine';
import type { WacRepository } from '../../../src/wac/WacRepository';

// This allows us to spy on randomUUID
jest.mock<typeof import('node:crypto')>('node:crypto', (): any => (
  { __esModule: true, ...jest.requireActual('node:crypto') }));

jest
  .useFakeTimers()
  .setSystemTime(new Date('1988-03-09'));

describe('WacPolicyEngine', (): void => {
  let uuidCounter: number;
  const uuidSpy = jest.spyOn(crypto, 'randomUUID');
  // eslint-disable-next-line no-plusplus
  uuidSpy.mockImplementation(((): string => `${uuidCounter++}`) as any);

  let checker: jest.Mocked<AccessChecker>;
  let repo: jest.Mocked<WacRepository>;
  let engine: WacPolicyEngine;

  let auths: WacAuthorization[];

  beforeEach(async(): Promise<void> => {
    uuidCounter = 1;
    uuidSpy.mockClear();

    auths = [{
      id: DataFactory.namedNode('http://example.com/#auth'),
      accessTo: [],
      default: [],
      agent: [ DataFactory.namedNode('http://example.com/agent') ],
      agentGroup: [],
      agentClass: [],
      mode: [ ACL.terms.Read, ACL.terms.Append ],
    }];

    checker = {
      handleSafe: jest.fn().mockResolvedValue({
        auth: auths[0],
        agent: { success: true, reason: 'http://example.com/agent' },
      }),
    } satisfies Partial<AccessChecker> as any;

    repo = {
      // eslint-disable-next-line unused-imports/no-unused-vars
      getRelevantAuthorizations: jest.fn(async function* (id: string): AsyncGenerator<WacAuthorization> {
        yield* auths;
      }),
    };

    engine = new WacPolicyEngine(checker, repo);
  });

  it('returns the correct permissions.', async(): Promise<void> => {
    await expect(engine.getPermissions('target', { agent: 'http://example.com/agent' }))
      .resolves.toEqual({
        [ACL.Read]: true,
        [ACL.Append]: true,
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
    });

    const expectedRdf = `
      @prefix acl: <http://www.w3.org/ns/auth/acl#>.
      @prefix dc: <http://purl.org/dc/terms/>.
      @prefix report: <urn:report:default:>.
      @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
      @prefix wacr: <urn:report:wac:>.
      
      <urn:uuid:1> a wacr:WacAclReport;
                   dc:created "1988-03-09T00:00:00.000Z"^^xsd:dateTime;
                   acl:agent <http://example.com/agent>;
                   report:target <http://example.com/>;
                   acl:mode acl:Read, acl:Append;
                   wacr:authReport <urn:uuid:2>.
      <urn:uuid:2> a wacr:WacAuthReport;
                   wacr:authorization <http://example.com/#auth>;
                   wacr:subjectReport <urn:uuid:3>.
      <urn:uuid:3> acl:agent <http://example.com/agent>.
    `;

    const expectedQuads = new Parser().parse(expectedRdf);
    expect(result.quads).toBeRdfIsomorphic(expectedQuads);
  });
});
