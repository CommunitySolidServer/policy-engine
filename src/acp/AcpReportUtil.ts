import { randomUUID } from 'node:crypto';
import type { NamedNode, Quad, Quad_Object } from '@rdfjs/types';
import { DataFactory, DataFactory as DF } from 'n3';
import type { PolicyReport } from '../PolicyEngine';
import { ACP, ACP_REPORT, DC, RDF, REPORT, XSD } from '../Vocabularies';
import type { Context } from './Acp';
import { isSuccessfulMatcher } from './AcpEvalUtil';
import type { AcpPolicyValidation, MatcherValidation } from './AcpPolicyValidation';

/**
 * Generates an ACP report, containing an explanation of how certain results got attained.
 *
 * @param contextNode - The subject identifier that is used to write down the ACP context in the report.
 * @param permissions - The permissions that have been determined.
 */
export function generateAcpReport(contextNode: Quad_Object, permissions: Record<string, {
  reason: AcpPolicyValidation;
  allow: boolean;
}>): PolicyReport {
  const quads: Quad[] = [];
  const id = DF.namedNode(`urn:uuid:${randomUUID()}`);
  quads.push(DF.quad(id, RDF.terms.type, ACP_REPORT.terms.AcpReport));
  quads.push(DF.quad(id, DC.terms.created, DF.literal(new Date().toISOString(), XSD.terms.dateTime)));
  quads.push(DF.quad(id, ACP.terms.context, contextNode));
  const policyReports: Record<string, NamedNode> = {};
  for (const [ permission, { reason, allow }] of Object.entries(permissions)) {
    if (!policyReports[reason.policy.iri]) {
      const policyReport = generatePolicyReport(reason);
      quads.push(...policyReport.quads);
      policyReports[reason.policy.iri] = policyReport.id;
    }
    quads.push(DF.quad(id, REPORT.terms[allow ? 'grant' : 'deny'], DF.namedNode(permission)));
    quads.push(DF.quad(id, ACP_REPORT.terms.policyReport, policyReports[reason.policy.iri]));
  }
  return { id, quads };
}

/**
 * Generates an RDF report for a single ACP policy.
 *
 * @param validation - The policy validation that needs a report.
 */
export function generatePolicyReport(validation: AcpPolicyValidation): PolicyReport {
  const quads: Quad[] = [];
  const id = DF.namedNode(`urn:uuid:${randomUUID()}`);
  quads.push(DF.quad(id, RDF.terms.type, ACP_REPORT.terms.PolicyReport));
  quads.push(DF.quad(id, ACP_REPORT.terms.policy, DF.namedNode(validation.policy.iri)));

  for (const constraint of [ 'allOf', 'anyOf', 'noneOf' ] as const) {
    if (!validation[constraint]) {
      continue;
    }
    // Success validation should have already happened by this point
    const { reason } = validation[constraint];
    const constraintReport = generateConstraintReport(constraint, reason);
    quads.push(DF.quad(id, ACP_REPORT.terms.constraintReport, constraintReport.id));
    quads.push(...constraintReport.quads);
  }
  return { id, quads };
}

/**
 * Generates an RDF report for a single constraint of an ACP policy.
 *
 * @param constraint - The constraint to report on.
 * @param reason - The reasons that were part of this constraint.
 */
export function generateConstraintReport(constraint: 'allOf' | 'anyOf' | 'noneOf', reason: MatcherValidation[]):
PolicyReport {
  const quads: Quad[] = [];

  const id = DF.namedNode(`urn:uuid:${randomUUID()}`);
  quads.push(DF.quad(id, ACP_REPORT.terms.constraint, ACP.terms[constraint]));
  for (const entry of reason) {
    const matcherNode = DF.namedNode(`urn:uuid:${randomUUID()}`);
    quads.push(DF.quad(id, REPORT.terms.proof, matcherNode));
    quads.push(DF.quad(matcherNode, ACP_REPORT.terms.matcher, DF.namedNode(entry.matcher.iri)));
    quads.push(DF.quad(
      matcherNode,
      ACP_REPORT.terms.success,
      DF.literal(`${isSuccessfulMatcher(entry)}`, XSD.terms.boolean),
    ));
    for (const key of Object.keys(entry) as (keyof MatcherValidation)[]) {
      if (key === 'matcher' || !entry[key]) {
        continue;
      }
      // `reason` being undefined means there we no values for this field
      const { success, reason } = entry[key];
      if (!success) {
        quads.push(DF.quad(matcherNode, ACP.terms[key], DF.literal('false', XSD.terms.boolean)));
      }
      if (!reason) {
        continue;
      }
      quads.push(DF.quad(matcherNode, ACP.terms[key], DF.namedNode(reason)));
    }
  }
  return { id, quads };
}

/**
 * Generates RDF quads to represent a context,
 * to be used in an ACP report.
 *
 * @param id - The subject identifier to use for the context quads.
 * @param context - The context to interpret.
 */
export function contextToQuads(id: NamedNode, context: Context): Quad[] {
  const result: Quad[] = [ DataFactory.quad(id, RDF.terms.type, ACP.terms.Context) ];
  for (const key of Object.keys(context) as (keyof Context)[]) {
    const vals = context[key] ?? [];
    const arrVals = Array.isArray(vals) ? vals : [ vals ];
    for (const val of arrVals) {
      result.push(DataFactory.quad(
        id,
        ACP.terms[key],
        DataFactory.namedNode(val),
      ));
    }
  }
  return result;
}
