import type { Matcher, Policy } from './Acp';

/**
 * A validation of an ACP Policy.
 * For each of the fields, this tracks if they were successful and what the reason for the result is.
 */
export interface AcpPolicyValidation {
  policy: Policy;
  allOf?: { success: boolean; reason: MatcherValidation[] };
  anyOf?: { success: boolean; reason: MatcherValidation[] };
  noneOf?: { success: boolean; reason: MatcherValidation[] };
}

/**
 * A validation of an ACP Matcher.
 * For each of the fields, this tracks if they were successful and what the reason for the result is.
 */
export interface MatcherValidation {
  matcher: Matcher;
  agent?: { success: boolean; reason?: string };
  client?: { success: boolean; reason?: string };
  issuer?: { success: boolean; reason?: string };
  vc?: { success: boolean; reason?: string };
}
