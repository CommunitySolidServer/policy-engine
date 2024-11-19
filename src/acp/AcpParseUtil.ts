import type { DatasetCore, NamedNode, Term } from '@rdfjs/types';
import { ACP } from '../Vocabularies';
import type { AccessControl, AccessControlResource, Matcher, Policy } from './Acp';

/**
 * Returns all objects found using the given subject and predicate, mapped with the given function.
 */
function mapObjects<T>(data: DatasetCore, sub: Term, pred: Term, fn: (data: DatasetCore, term: Term) => T): T[] {
  const results: T[] = [];
  for (const quad of data.match(sub, pred)) {
    results.push(fn(data, quad.object));
  }
  return results;
}

/**
 * Returns the string values of all objects found using the given subject and predicate.
 */
function getObjectValues(data: DatasetCore, subject: Term, predicate: NamedNode): string[] {
  return mapObjects(data, subject, predicate, (unused, term): string => term.value);
}

/**
 * Finds the {@link Matcher} with the given identifier in the given dataset.
 *
 * @param data - Dataset to look in.
 * @param matcher - Identifier of the matcher.
 */
export function getMatcher(data: DatasetCore, matcher: Term): Matcher {
  return {
    iri: matcher.value,
    agent: getObjectValues(data, matcher, ACP.terms.agent),
    client: getObjectValues(data, matcher, ACP.terms.client),
    issuer: getObjectValues(data, matcher, ACP.terms.issuer),
    vc: getObjectValues(data, matcher, ACP.terms.vc),
  };
}

/**
 * Finds the {@link Policy} with the given identifier in the given dataset.
 *
 * @param data - Dataset to look in.
 * @param policy - Identifier of the policy.
 */
export function getPolicy(data: DatasetCore, policy: Term): Policy {
  return {
    iri: policy.value,
    allow: new Set(getObjectValues(data, policy, ACP.terms.allow)),
    deny: new Set(getObjectValues(data, policy, ACP.terms.deny)),
    allOf: mapObjects(data, policy, ACP.terms.allOf, getMatcher),
    anyOf: mapObjects(data, policy, ACP.terms.anyOf, getMatcher),
    noneOf: mapObjects(data, policy, ACP.terms.noneOf, getMatcher),
  };
}

/**
 * Finds the {@link AccessControl} with the given identifier in the given dataset.
 *
 * @param data - Dataset to look in.
 * @param accessControl - Identifier of the access control.
 */
export function getAccessControl(data: DatasetCore, accessControl: Term): AccessControl {
  const policy = mapObjects(data, accessControl, ACP.terms.apply, getPolicy);
  return {
    iri: accessControl.value,
    policy,
  };
}

/**
 * Finds the {@link AccessControlResource} with the given identifier in the given dataset.
 *
 * @param data - Dataset to look in.
 * @param acr - Identifier of the access control resource.
 */
export function getAccessControlResource(data: DatasetCore, acr: Term): AccessControlResource {
  const resource: string[] = [];
  for (const quad of data.match(acr, ACP.terms.resource)) {
    resource.push(quad.object.value);
  }

  const accessControl: AccessControl[] = [];
  for (const quad of data.match(acr, ACP.terms.accessControl)) {
    accessControl.push(getAccessControl(data, quad.object));
  }

  const memberAccessControl: AccessControl[] = [];
  for (const quad of data.match(acr, ACP.terms.memberAccessControl)) {
    memberAccessControl.push(getAccessControl(data, quad.object));
  }
  return {
    iri: acr.value,
    resource,
    accessControl,
    memberAccessControl,
  };
}

/**
 * Finds all {@link AccessControlResource} in the given dataset.
 *
 * @param data - Dataset to look in.
 */
export function* getAccessControlResources(data: DatasetCore): Generator<AccessControlResource, void> {
  const acrQuads = data.match(undefined, ACP.terms.resource);

  const cache: Record<string, boolean> = {};

  for (const quad of acrQuads) {
    if (cache[quad.subject.value]) {
      continue;
    }
    cache[quad.subject.value] = true;
    yield getAccessControlResource(data, quad.subject);
  }
}

/**
 * Returns all {@link Policy} found in `resources` that apply to the target identifier.
 * https://solidproject.org/TR/2022/acp-20220518#effective-policies
 */
export function* getEffectivePolicies(target: string, acr: AccessControlResource): Generator<Policy, void> {
  // Use the ACR if the `target` is included in the list of resources.
  // If not, this means this is an ACR of a parent resource, and we need to use the `memberAccessControl` field.
  const accessControlField = acr.resource.includes(target) ? 'accessControl' : 'memberAccessControl';
  const policies = acr[accessControlField].flatMap((ac): Policy[] => ac.policy);
  yield* policies;
}
