import type { PermissionMap } from '../PolicyEngine';
import { ACP } from '../Vocabularies';
import type { Context, Matcher, Policy } from './Acp';
import type { AcpPolicyValidation, MatcherValidation } from './AcpPolicyValidation';

export type AcpPermissionMap = Record<string, { reason: AcpPolicyValidation; allow: boolean }>;

/**
 * Removes the reasons from an {@link AcpPermissionMap}, only keeping the permissions.
 *
 * @param map - Map to remove reasons from.
 */
export function removeAcpReasons(map: AcpPermissionMap): PermissionMap {
  return Object.fromEntries(Object.entries(map).map(([ perm, { allow }]): [string, boolean] => [ perm, allow ]));
}

/**
 * Evaluates if a policy validation indicates if the policy succeeded or not.
 *
 * @param validation - Validation to evaluate.
 */
export function isSuccessfulPolicy(validation: AcpPolicyValidation): boolean {
  // The ACP spec says a policy needs at least 1 matcher linked through acp:anyOf or acp:allOf.
  // We are being a bit broader here by also succeeding if a policy only links to matchers through acp:noneOf.
  let success = false;
  for (const key of Object.keys(validation) as (keyof AcpPolicyValidation)[]) {
    if (key === 'policy' || !validation[key]) {
      continue;
    }
    if (!validation[key].success) {
      return false;
    }
    success = true;
  }
  return success;
}

/**
 * Validates a policy based on the given context.
 *
 * @param policy - Policy to validate.
 * @param context - Context to use.
 */
export function validatePolicy(policy: Policy, context: Context): AcpPolicyValidation {
  const validation: AcpPolicyValidation = { policy };

  // All of
  if (policy.allOf.length > 0) {
    validation.allOf = { success: true, reason: []};
    for (const matcher of policy.allOf) {
      const matcherResult = validateMatcher(matcher, context);
      if (!isSuccessfulMatcher(matcherResult)) {
        validation.allOf = { success: false, reason: [ matcherResult ]};
        break;
      }
      validation.allOf.reason.push(matcherResult);
    }
  }

  // Any of
  if (policy.anyOf.length > 0) {
    validation.anyOf = { success: false, reason: []};
    for (const matcher of policy.anyOf) {
      const matcherResult = validateMatcher(matcher, context);
      if (isSuccessfulMatcher(matcherResult)) {
        validation.anyOf = { success: true, reason: [ matcherResult ]};
        break;
      }
      validation.anyOf.reason.push(matcherResult);
    }
  }

  // None of
  if (policy.noneOf.length > 0) {
    validation.noneOf = { success: true, reason: []};
    for (const matcher of policy.noneOf) {
      const matcherResult = validateMatcher(matcher, context);
      if (isSuccessfulMatcher(matcherResult)) {
        validation.noneOf = { success: false, reason: [ matcherResult ]};
        break;
      }
      validation.noneOf.reason.push(matcherResult);
    }
  }

  return validation;
}

/**
 * Evaluates if a matches validation indicates if the matcher succeeded or not.
 *
 * @param validation - Validation to evaluate.
 */
export function isSuccessfulMatcher(validation: MatcherValidation): boolean {
  // At least one field needs to validate for this to be a success
  let success = false;
  for (const key of Object.keys(validation) as (keyof MatcherValidation)[]) {
    if (key === 'matcher' || !validation[key]) {
      continue;
    }
    if (!validation[key].success) {
      return false;
    }
    success = true;
  }
  return success;
}

/**
 * Validates a matcher based on the given context.
 *
 * @param matcher - Matcher to validate.
 * @param context - Context to use.
 */
export function validateMatcher(matcher: Matcher, context: Context): MatcherValidation {
  const result: MatcherValidation = { matcher };
  for (const key of [ 'agent', 'client', 'issuer', 'vc' ] as const) {
    if (matcher[key].length > 0) {
      result[key] = validateMatcherEntry(context, matcher[key], getEvaluationFn(key));
    }
  }
  return result;
}

/**
 * Helper function for {@link validateMatcher}.
 * Validates one entry of a matcher object.
 *
 * @param context - Context to use.
 * @param values - The values for the entry of the matcher.
 * @param fn - The function to validate those values with.
 */
export function validateMatcherEntry(
  context: Context,
  values: string[],
  fn: (val: string, context: Context) => boolean,
): { success: boolean; reason?: string } | undefined {
  if (values.length === 0) {
    return;
  }
  for (const value of values) {
    if (fn(value, context)) {
      return { success: true, reason: value };
    }
  }
  return { success: false };
}

/**
 *
 * Helper function for {@link validateMatcher}.
 * Returns the correct validation function for the given entry key.
 *
 * @param key - The key of the entry of the matcher that needs to be validated.
 */
export function getEvaluationFn(key: string): (val: string, context: Context) => boolean {
  switch (key) {
    case 'agent': return evaluateAgent;
    case 'client': return evaluateClient;
    case 'issuer': return evaluateIssuer;
    case 'vc': return evaluateVc;
    default: throw new Error(`No matching evaluation fn for key ${key}`);
  }
}

/**
 * Evaluates a matcher agent value against a context.
 *
 * @param agent - One of the matcher agent entries.
 * @param context - Context to use.
 */
export function evaluateAgent(agent: string, context: Context): boolean {
  // Based on https://github.com/solid-contrib/access-control-policy/blob/main/src/algorithm/match_agent.ts
  // The ACP Public Agent matches every context
  if (agent === ACP.PublicAgent) {
    return true;
  }
  // Can't match the agent if it's not defined
  if (!context.agent) {
    return false;
  }
  // The ACP AuthenticatedAgent matches any defined context agent
  if (agent === ACP.AuthenticatedAgent) {
    return true;
  }
  // The ACP Creator Agent matches context agent and context creator
  if (agent === ACP.CreatorAgent) {
    return Boolean(context.creator?.includes(context.agent));
  }
  // The ACP Owner Agent matches context agent and context owner
  if (agent === ACP.OwnerAgent) {
    return Boolean(context.owner?.includes(context.agent));
  }
  // The context agent matches a matching agent
  return agent === context.agent;
}

/**
 * Evaluates a matcher client value against a context.
 *
 * @param client - One of the matcher client entries.
 * @param context - Context to use.
 */
export function evaluateClient(client: string, context: Context): boolean {
  return client === ACP.PublicClient || client === context.client;
}

/**
 * Evaluates a issuer client value against a context.
 *
 * @param issuer - One of the matcher issuer entries.
 * @param context - Context to use.
 */
export function evaluateIssuer(issuer: string, context: Context): boolean {
  return issuer === context.issuer;
}

/**
 * Evaluates a vc client value against a context.
 *
 * @param vc - One of the matcher vc entries.
 * @param context - Context to use.
 */
export function evaluateVc(vc: string, context: Context): boolean {
  return Boolean(context.vc && context.vc.includes(vc));
}
