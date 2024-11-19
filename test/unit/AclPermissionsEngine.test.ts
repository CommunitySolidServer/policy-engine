import 'jest-rdf';
import * as crypto from 'node:crypto';
import { DataFactory, Parser } from 'n3';
import { AclPermissionsEngine } from '../../src/AclPermissionsEngine';
import type { AuthorizationManager } from '../../src/AuthorizationManager';
import type { PolicyEngine } from '../../src/PolicyEngine';
import { ACL, PERMISSIONS, RDF, WAC_REPORT } from '../../src/Vocabularies';

// This allows us to spy on randomUUID
jest.mock<typeof import('node:crypto')>('node:crypto', (): any => (
  { __esModule: true, ...jest.requireActual('node:crypto') }));

jest
  .useFakeTimers()
  .setSystemTime(new Date('1988-03-09'));

describe('AclPermissionsEngine', (): void => {
  let uuidCounter: number;
  const uuidSpy = jest.spyOn(crypto, 'randomUUID');
  // eslint-disable-next-line no-plusplus
  uuidSpy.mockImplementation(((): string => `${uuidCounter++}`) as any);

  let policyEngine: jest.Mocked<PolicyEngine>;
  let manager: jest.Mocked<AuthorizationManager>;
  let engine: AclPermissionsEngine;

  beforeEach(async(): Promise<void> => {
    uuidCounter = 1;
    uuidSpy.mockClear();

    policyEngine = {
      getPermissions: jest.fn(),
      getPermissionsWithReport: jest.fn(),
    };

    manager = {
      getParent: jest.fn(),
      getAuthorizationData: jest.fn(),
    };

    engine = new AclPermissionsEngine(policyEngine, manager);
  });

  it('calls both target and parent to convert ACL permissions.', async(): Promise<void> => {
    manager.getParent.mockReturnValueOnce('parent');
    policyEngine.getPermissions.mockResolvedValueOnce({ [ACL.Write]: true, [ACL.Read]: false });
    policyEngine.getPermissions.mockResolvedValueOnce({ [ACL.Write]: false, [ACL.Append]: true });
    await expect(engine.getPermissions('target', {})).resolves.toEqual({
      [PERMISSIONS.Append]: true,
      [PERMISSIONS.Modify]: true,
      [PERMISSIONS.Create]: true,
      [PERMISSIONS.Delete]: false,
      [PERMISSIONS.Read]: false,
      [ACL.Append]: true,
      [ACL.Read]: false,
      [ACL.Write]: true,
    });
    expect(manager.getParent).toHaveBeenCalledTimes(1);
    expect(policyEngine.getPermissions).toHaveBeenCalledTimes(2);
  });

  it('does not check parent permissions if not necessary.', async(): Promise<void> => {
    manager.getParent.mockReturnValueOnce('parent');
    policyEngine.getPermissions.mockResolvedValueOnce({ [ACL.Write]: true, [ACL.Read]: false });
    policyEngine.getPermissions.mockResolvedValueOnce({ [ACL.Write]: false, [ACL.Append]: true });
    await expect(engine.getPermissions('target', {}, [ PERMISSIONS.Append, PERMISSIONS.Read ])).resolves.toEqual({
      [PERMISSIONS.Append]: true,
      [PERMISSIONS.Modify]: true,
      [PERMISSIONS.Read]: false,
      [ACL.Append]: true,
      [ACL.Read]: false,
      [ACL.Write]: true,
    });
    expect(manager.getParent).toHaveBeenCalledTimes(0);
    expect(policyEngine.getPermissions).toHaveBeenCalledTimes(1);
  });

  it('does check the parent permissions if a relevant permission is requested.', async(): Promise<void> => {
    manager.getParent.mockReturnValueOnce('parent');
    policyEngine.getPermissions.mockResolvedValueOnce({ [ACL.Write]: true, [ACL.Read]: false });
    policyEngine.getPermissions.mockResolvedValueOnce({ [ACL.Write]: false, [ACL.Append]: true });
    await expect(engine.getPermissions('target', {}, [ PERMISSIONS.Create ])).resolves.toEqual({
      [PERMISSIONS.Append]: true,
      [PERMISSIONS.Modify]: true,
      [PERMISSIONS.Create]: true,
      [PERMISSIONS.Delete]: false,
      [PERMISSIONS.Read]: false,
      [ACL.Append]: true,
      [ACL.Read]: false,
      [ACL.Write]: true,
    });
    expect(manager.getParent).toHaveBeenCalledTimes(1);
    expect(policyEngine.getPermissions).toHaveBeenCalledTimes(2);
  });

  it('combines reports.', async(): Promise<void> => {
    const targetId = DataFactory.namedNode('targetReport');
    const parentId = DataFactory.namedNode('parentReport');
    manager.getParent.mockReturnValueOnce('parent');
    policyEngine.getPermissionsWithReport.mockResolvedValueOnce({
      id: targetId,
      permissions: { [ACL.Write]: true, [ACL.Read]: false },
      quads: [ DataFactory.quad(targetId, RDF.terms.type, WAC_REPORT.terms.WacAclReport) ],
    });
    policyEngine.getPermissionsWithReport.mockResolvedValueOnce({
      id: parentId,
      permissions: { [ACL.Write]: false, [ACL.Append]: true },
      quads: [ DataFactory.quad(parentId, RDF.terms.type, WAC_REPORT.terms.WacAclReport) ],
    });
    const result = await engine.getPermissionsWithReport('target', {});
    expect(result.permissions).toEqual({
      [PERMISSIONS.Append]: true,
      [PERMISSIONS.Modify]: true,
      [PERMISSIONS.Create]: true,
      [PERMISSIONS.Delete]: false,
      [PERMISSIONS.Read]: false,
      [ACL.Append]: true,
      [ACL.Read]: false,
      [ACL.Write]: true,
    });
    expect(manager.getParent).toHaveBeenCalledTimes(1);
    expect(policyEngine.getPermissionsWithReport).toHaveBeenCalledTimes(2);

    const expectedRdf = `
      @prefix acl: <http://www.w3.org/ns/auth/acl#>.
      @prefix dc: <http://purl.org/dc/terms/>.
      @prefix report: <urn:report:default:>.
      @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
      @prefix wacr: <urn:report:wac:>.
      
      <urn:uuid:1> a report:Report;
                   report:target <target>;
                   report:grant <${PERMISSIONS.Append}>;
                   report:grant <${PERMISSIONS.Modify}>;
                   report:grant <${PERMISSIONS.Create}>;
                   report:deny <${PERMISSIONS.Delete}>;
                   report:deny <${PERMISSIONS.Read}>;
                   report:grant <${ACL.Append}>;
                   report:deny <${ACL.Read}>;
                   report:grant <${ACL.Write}>;
                   report:proof <targetReport>;
                   report:proof <parentReport>.
      <targetReport> a wacr:WacAclReport.
      <parentReport> a wacr:WacAclReport.
    `;

    const expectedQuads = new Parser().parse(expectedRdf);

    expect(result.quads).toBeRdfIsomorphic(expectedQuads);
  });

  it('does not check the parent report if not necessary.', async(): Promise<void> => {
    const targetId = DataFactory.namedNode('targetReport');
    const parentId = DataFactory.namedNode('parentReport');
    manager.getParent.mockReturnValueOnce('parent');
    policyEngine.getPermissionsWithReport.mockResolvedValueOnce({
      id: targetId,
      permissions: { [ACL.Write]: true, [ACL.Read]: false },
      quads: [ DataFactory.quad(targetId, RDF.terms.type, WAC_REPORT.terms.WacAclReport) ],
    });
    policyEngine.getPermissionsWithReport.mockResolvedValueOnce({
      id: parentId,
      permissions: { [ACL.Write]: false, [ACL.Append]: true },
      quads: [ DataFactory.quad(parentId, RDF.terms.type, WAC_REPORT.terms.WacAclReport) ],
    });
    const result = await engine.getPermissionsWithReport('target', {}, [ PERMISSIONS.Modify, PERMISSIONS.Read ]);
    expect(result.permissions).toEqual({
      [PERMISSIONS.Append]: true,
      [PERMISSIONS.Modify]: true,
      [PERMISSIONS.Read]: false,
      [ACL.Append]: true,
      [ACL.Read]: false,
      [ACL.Write]: true,
    });
    expect(manager.getParent).toHaveBeenCalledTimes(0);
    expect(policyEngine.getPermissionsWithReport).toHaveBeenCalledTimes(1);

    const expectedRdf = `
      @prefix acl: <http://www.w3.org/ns/auth/acl#>.
      @prefix dc: <http://purl.org/dc/terms/>.
      @prefix report: <urn:report:default:>.
      @prefix xsd: <http://www.w3.org/2001/XMLSchema#>.
      @prefix wacr: <urn:report:wac:>.
      
      <urn:uuid:1> a report:Report;
                   report:target <target>;
                   report:grant <${PERMISSIONS.Append}>;
                   report:grant <${PERMISSIONS.Modify}>;
                   report:deny <${PERMISSIONS.Read}>;
                   report:grant <${ACL.Append}>;
                   report:deny <${ACL.Read}>;
                   report:grant <${ACL.Write}>;
                   report:proof <targetReport>.
      <targetReport> a wacr:WacAclReport.
    `;

    const expectedQuads = new Parser().parse(expectedRdf);

    expect(result.quads).toBeRdfIsomorphic(expectedQuads);
  });
});
