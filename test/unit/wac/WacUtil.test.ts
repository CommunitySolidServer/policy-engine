import 'jest-rdf';
import * as crypto from 'node:crypto';
import { DataFactory, Parser } from 'n3';
import { ACL } from '../../../src/Vocabularies';
import type { WacAuthValidation } from '../../../src/wac/WacAuthValidation';
import type {
  WacPermissionMap,
} from '../../../src/wac/WacUtil';
import {
  generateWacReport,
  isSuccessfulAuthorization,
  removeWacReasons,
} from '../../../src/wac/WacUtil';

// This allows us to spy on randomUUID
jest.mock<typeof import('node:crypto')>('node:crypto', (): any => (
  { __esModule: true, ...jest.requireActual('node:crypto') }));

jest
  .useFakeTimers()
  .setSystemTime(new Date('1988-03-09'));

describe('WacUtil', (): void => {
  let uuidCounter: number;
  const uuidSpy = jest.spyOn(crypto, 'randomUUID');
  // eslint-disable-next-line no-plusplus
  uuidSpy.mockImplementation(((): string => `${uuidCounter++}`) as any);

  beforeEach(async(): Promise<void> => {
    uuidCounter = 1;
    uuidSpy.mockClear();
  });

  describe('#removeWacReasons', (): void => {
    it('removes the reasons from a WAC permission map.', async(): Promise<void> => {
      const map: WacPermissionMap = {
        read: { allow: true, reason: { auth: 'auth' as any }},
      };
      expect(removeWacReasons(map)).toEqual({
        read: true,
      });
    });
  });

  describe('#isSuccessfulAuthorization', (): void => {
    it('returns true if there is at least one success.', async(): Promise<void> => {
      expect(isSuccessfulAuthorization({ auth: 'auth' as any, agent: { success: true }})).toBe(true);
    });

    it('returns false if there is no success.', async(): Promise<void> => {
      expect(isSuccessfulAuthorization({ auth: 'auth' as any })).toBe(false);
    });
  });

  describe('generateWacReport', (): void => {
    it('returns a valid report.', async(): Promise<void> => {
      const validation: WacAuthValidation = {
        auth: {
          id: DataFactory.namedNode('http://example.com/#auth'),
        } as any,
        agent: { success: true, reason: 'http://example.com/agent' },
      };

      const result = generateWacReport({
        [ACL.Read]: { allow: true, reason: validation },
        [ACL.Append]: { allow: true, reason: validation },
      }, 'http://example.com/', 'http://example.com/agent');

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
});
