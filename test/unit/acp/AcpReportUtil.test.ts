import 'jest-rdf';
import type { NamedNode } from '@rdfjs/types';
import { DataFactory } from 'n3';
import type { Context } from '../../../src/acp/Acp';
import type { AcpPolicyValidation, MatcherValidation } from '../../../src/acp/AcpPolicyValidation';
import { contextToQuads, generateAcpReport } from '../../../src/acp/AcpReportUtil';
import { ACL, ACP, ACP_REPORT, DC, RDF, REPORT, XSD } from '../../../src/Vocabularies';

jest
  .useFakeTimers()
  .setSystemTime(new Date('1988-03-09'));

describe('AcpReportUtil', (): void => {
  describe('#generateAcpReport', (): void => {
    const matcherValidation: MatcherValidation = {
      matcher: { iri: 'matcher1' } as any,
      agent: { success: true, reason: ACP.PublicAgent },
      client: { success: false },
    };
    const policyValidation: AcpPolicyValidation = {
      policy: { iri: 'policy' } as any,
      allOf: { success: false, reason: [ matcherValidation ]},
    };
    const permissions: Record<string, { reason: AcpPolicyValidation; allow: boolean }> = {
      [ACL.Read]: { reason: policyValidation, allow: false },
    };

    it('generates a report.', async(): Promise<void> => {
      const contextNode = DataFactory.namedNode('contextNode');
      const result = generateAcpReport(contextNode, permissions);
      const policyId = result.quads.find((quad): boolean =>
        quad.subject.equals(result.id) && quad.predicate.equals(ACP_REPORT.terms.policyReport))?.object as NamedNode;
      expect(policyId?.termType).toBe('NamedNode');
      const constraintId = result.quads.find((quad): boolean =>
        quad.subject.equals(policyId) && quad.predicate.equals(ACP_REPORT.terms.constraintReport))?.object as NamedNode;
      expect(constraintId?.termType).toBe('NamedNode');
      const proofId = result.quads.find((quad): boolean =>
        quad.subject.equals(constraintId) && quad.predicate.equals(REPORT.terms.proof))?.object as NamedNode;
      expect(proofId?.termType).toBe('NamedNode');

      expect(result.quads).toBeRdfIsomorphic([
        DataFactory.quad(result.id, RDF.terms.type, ACP_REPORT.terms.AcpReport),
        DataFactory.quad(result.id, DC.terms.created, DataFactory
          .literal('1988-03-09T00:00:00.000Z', XSD.terms.dateTime)),
        DataFactory.quad(result.id, ACP.terms.context, contextNode),
        DataFactory.quad(result.id, REPORT.terms.deny, ACL.terms.Read),
        DataFactory.quad(result.id, ACP_REPORT.terms.policyReport, policyId),
        DataFactory.quad(policyId, RDF.terms.type, ACP_REPORT.terms.PolicyReport),
        DataFactory.quad(policyId, ACP_REPORT.terms.policy, DataFactory.namedNode('policy')),
        DataFactory.quad(policyId, ACP_REPORT.terms.constraintReport, constraintId),
        DataFactory.quad(constraintId, ACP_REPORT.terms.constraint, ACP.terms.allOf),
        DataFactory.quad(constraintId, REPORT.terms.proof, proofId),
        DataFactory.quad(proofId, ACP_REPORT.terms.matcher, DataFactory.namedNode('matcher1')),
        DataFactory.quad(proofId, ACP_REPORT.terms.success, DataFactory.literal('false', XSD.terms.boolean)),
        DataFactory.quad(proofId, ACP.terms.agent, ACP.terms.PublicAgent),
        DataFactory.quad(proofId, ACP.terms.client, DataFactory.literal('false', XSD.terms.boolean)),
      ]);
    });
  });

  describe('#contextToQuads', (): void => {
    it('converts a context to quads.', async(): Promise<void> => {
      const context: Context = {
        target: 'target',
        owner: [ 'owner1', 'owner2' ],
        agent: 'agent',
        client: 'client',
      };
      const id = DataFactory.namedNode('id');
      expect(contextToQuads(id, context)).toBeRdfIsomorphic([
        DataFactory.quad(id, RDF.terms.type, ACP.terms.Context),
        DataFactory.quad(id, ACP.terms.target, DataFactory.namedNode('target')),
        DataFactory.quad(id, ACP.terms.owner, DataFactory.namedNode('owner1')),
        DataFactory.quad(id, ACP.terms.owner, DataFactory.namedNode('owner2')),
        DataFactory.quad(id, ACP.terms.agent, DataFactory.namedNode('agent')),
        DataFactory.quad(id, ACP.terms.client, DataFactory.namedNode('client')),
      ]);
    });
  });
});
