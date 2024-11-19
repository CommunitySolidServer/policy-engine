import { randomUUID } from 'node:crypto';
import type { NamedNode, Quad } from '@rdfjs/types';
import { DataFactory as DF } from 'n3';
import type { PermissionMap, PolicyReport } from '../PolicyEngine';
import { ACL, DC, FOAF, RDF, REPORT, WAC_REPORT, XSD } from '../Vocabularies';
import type { WacAuthValidation } from './WacAuthValidation';

export type WacPermissionMap = Record<string, { reason: WacAuthValidation; allow: boolean }>;

/**
 * Removes the reasons from a {@link WacPermissionMap}, only keeping the permissions.
 *
 * @param map - Map to remove reasons from.
 */
export function removeWacReasons(map: WacPermissionMap): PermissionMap {
  return Object.fromEntries(Object.entries(map).map(([ perm, { allow }]): [string, boolean] => [ perm, allow ]));
}

/**
 * Evaluates if an authorization validation indicates if the policy succeeded or not.
 *
 * @param validation - Validation to evaluate.
 */
export function isSuccessfulAuthorization(validation: WacAuthValidation): boolean {
  // Note that for WAC just one of the access subjects needs to be valid
  for (const key of Object.keys(validation) as (keyof WacAuthValidation)[]) {
    if (key === 'auth' || !validation[key]) {
      continue;
    }
    if (validation[key].success) {
      return true;
    }
  }
  return false;
}

/**
 * Generates a WAC report, containing an explanation of how certain results got attained.
 *
 * @param permissions - The permissions that have been determined.
 * @param target - The target resource for which the report is being generated.
 * @param agent - The agent that wants to access the resource.
 */
export function generateWacReport(
  permissions: Record<string, { reason: WacAuthValidation; allow: boolean }>,
  target: string,
  agent?: string,
): PolicyReport {
  const quads: Quad[] = [];
  const id = DF.namedNode(`urn:uuid:${randomUUID()}`);
  quads.push(DF.quad(id, RDF.terms.type, WAC_REPORT.terms.WacAclReport));
  quads.push(DF.quad(id, DC.terms.created, DF.literal(new Date().toISOString(), XSD.terms.dateTime)));
  if (agent) {
    quads.push(DF.quad(id, ACL.terms.agent, DF.namedNode(agent)));
  } else {
    quads.push(DF.quad(id, ACL.terms.agentClass, FOAF.terms.Agent));
  }
  quads.push(DF.quad(id, REPORT.terms.target, DF.namedNode(target)));

  const authReports: Record<string, NamedNode> = {};
  for (const [ permission, { reason }] of Object.entries(permissions)) {
    if (!authReports[reason.auth.id.value]) {
      const report = generateWacAuthReport(reason);
      quads.push(...report.quads);
      authReports[reason.auth.id.value] = report.id;
    }
    quads.push(DF.quad(id, ACL.terms.mode, DF.namedNode(permission)));
    quads.push(DF.quad(id, WAC_REPORT.terms.authReport, authReports[reason.auth.id.value]));
  }

  return { id, quads };
}

/**
 * Generates an RDF report for a single WAC authorization.
 *
 * @param validation - The authorization validation that needs a report.
 */
export function generateWacAuthReport(validation: WacAuthValidation): PolicyReport {
  const quads: Quad[] = [];
  const id = DF.namedNode(`urn:uuid:${randomUUID()}`);
  quads.push(DF.quad(id, RDF.terms.type, WAC_REPORT.terms.WacAuthReport));
  quads.push(DF.quad(id, WAC_REPORT.terms.authorization, validation.auth.id));

  for (const key of Object.keys(validation) as (keyof WacAuthValidation)[]) {
    if (key === 'auth' || !validation[key]) {
      continue;
    }
    const subjectNode = DF.namedNode(`urn:uuid:${randomUUID()}`);
    quads.push(DF.quad(id, WAC_REPORT.terms.subjectReport, subjectNode));
    if (!validation[key].success) {
      quads.push(DF.quad(subjectNode, ACL.terms[key], DF.literal('false', XSD.terms.boolean)));
    } else if (validation[key]?.reason) {
      quads.push(DF.quad(subjectNode, ACL.terms[key], DF.namedNode(validation[key].reason)));
    }
  }

  return { id, quads };
}
