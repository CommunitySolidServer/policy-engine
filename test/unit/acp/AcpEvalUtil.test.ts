import type { Context, Matcher, Policy } from '../../../src/acp/Acp';
import type {
  AcpPermissionMap,
} from '../../../src/acp/AcpEvalUtil';
import {
  evaluateAgent,
  evaluateClient,
  evaluateIssuer,
  evaluateVc,
  isSuccessfulMatcher,
  isSuccessfulPolicy,
  removeAcpReasons,
  validateMatcher,
  validatePolicy,
} from '../../../src/acp/AcpEvalUtil';
import type { AcpPolicyValidation, MatcherValidation } from '../../../src/acp/AcpPolicyValidation';

describe('AcpEvalUtil', (): void => {
  describe('#removeAcpReasons', (): void => {
    it('removes the reasons from an ACP permission map.', async(): Promise<void> => {
      const map: AcpPermissionMap = {
        read: { allow: true, reason: { policy: 'policy' as any }},
        write: { allow: false, reason: { policy: 'policy' as any }},
      };
      expect(removeAcpReasons(map)).toEqual({
        read: true,
        write: false,
      });
    });
  });

  describe('#isSuccessfulPolicy', (): void => {
    it('returns false for policies having no matchers.', async(): Promise<void> => {
      const validation: AcpPolicyValidation = { policy: 'policy' as any };
      expect(isSuccessfulPolicy(validation)).toBe(false);
    });

    it('returns true if all present matcher sets succeed.', async(): Promise<void> => {
      const validation: AcpPolicyValidation = {
        policy: 'policy' as any,
        allOf: { success: true, reason: []},
        noneOf: { success: true, reason: []},
      };
      expect(isSuccessfulPolicy(validation)).toBe(true);
    });

    it('returns false if at least one matcher set fails.', async(): Promise<void> => {
      const validation: AcpPolicyValidation = {
        policy: 'policy' as any,
        allOf: { success: true, reason: []},
        anyOf: { success: true, reason: []},
        noneOf: { success: false, reason: []},
      };
      expect(isSuccessfulPolicy(validation)).toBe(false);
    });
  });

  describe('#validatePolicy', (): void => {
    const context: Context = { target: 'target', agent: 'agent' };
    const successMatcher: Matcher = { iri: 'success', agent: [ 'agent' ], client: [], issuer: [], vc: []};
    const failureMatcher: Matcher = { iri: 'failure', agent: [ 'other' ], client: [], issuer: [], vc: []};
    const successValidation: MatcherValidation = { matcher: successMatcher, agent: { success: true, reason: 'agent' }};
    const failureValidation: MatcherValidation = { matcher: failureMatcher, agent: { success: false }};

    it('validates a policy.', async(): Promise<void> => {
      const policy: Policy = {
        iri: 'policy',
        allow: new Set(),
        deny: new Set(),
        noneOf: [ failureMatcher ],
        anyOf: [ successMatcher, failureMatcher ],
        allOf: [ successMatcher, failureMatcher ],
      };
      expect(validatePolicy(policy, context)).toEqual({
        policy,
        noneOf: { success: true, reason: [ failureValidation ]},
        anyOf: { success: true, reason: [ successValidation ]},
        allOf: { success: false, reason: [ failureValidation ]},
      });
    });
  });

  describe('#isSuccessfulMatcher', (): void => {
    it('returns false for matchers with no attributes.', async(): Promise<void> => {
      const matcher: MatcherValidation = { matcher: 'matcher' as any };
      expect(isSuccessfulMatcher(matcher)).toBe(false);
    });

    it('returns true if all present attributes succeed.', async(): Promise<void> => {
      const matcher: MatcherValidation = {
        matcher: 'matcher' as any,
        client: { success: true },
        agent: { success: true },
      };
      expect(isSuccessfulMatcher(matcher)).toBe(true);
    });

    it('returns false if at least one attribute fails.', async(): Promise<void> => {
      const matcher: MatcherValidation = {
        matcher: 'matcher' as any,
        client: { success: true },
        agent: { success: true },
        issuer: { success: false },
      };
      expect(isSuccessfulMatcher(matcher)).toBe(false);
    });
  });

  describe('#validateMatcher', (): void => {
    it('validates a matcher.', async(): Promise<void> => {
      const matcher: Matcher = {
        iri: 'matcher',
        agent: [ 'http://www.w3.org/ns/solid/acp#PublicAgent' ],
        client: [],
        issuer: [ 'issuer' ],
        vc: [ 'vc' ],
      };
      expect(validateMatcher(matcher, { target: 'target', issuer: 'issuer' })).toEqual({
        matcher,
        agent: { success: true, reason: 'http://www.w3.org/ns/solid/acp#PublicAgent' },
        issuer: { success: true, reason: 'issuer' },
        vc: { success: false },
      });
    });
  });

  describe('#evaluateAgent', (): void => {
    it('returns true for public agents.', async(): Promise<void> => {
      expect(evaluateAgent('http://www.w3.org/ns/solid/acp#PublicAgent', { target: 'target' })).toBe(true);
    });

    it('otherwise returns false if there is no context agent.', async(): Promise<void> => {
      expect(evaluateAgent('http://www.w3.org/ns/solid/acp#AuthenticatedAgent', { target: 'target' })).toBe(false);
    });

    it('returns true for an authenticated agent if it is in the context.', async(): Promise<void> => {
      expect(evaluateAgent(
        'http://www.w3.org/ns/solid/acp#AuthenticatedAgent',
        { target: 'target', agent: 'agent' },
      )).toBe(true);
    });

    it('can match owners or creators.', async(): Promise<void> => {
      expect(evaluateAgent(
        'http://www.w3.org/ns/solid/acp#CreatorAgent',
        { target: 'target', agent: 'agent' },
      )).toBe(false);
      expect(evaluateAgent(
        'http://www.w3.org/ns/solid/acp#CreatorAgent',
        { target: 'target', agent: 'agent', creator: [ 'agent' ]},
      )).toBe(true);

      expect(evaluateAgent(
        'http://www.w3.org/ns/solid/acp#OwnerAgent',
        { target: 'target', agent: 'agent' },
      )).toBe(false);
      expect(evaluateAgent(
        'http://www.w3.org/ns/solid/acp#OwnerAgent',
        { target: 'target', agent: 'agent', owner: [ 'agent' ]},
      )).toBe(true);
    });

    it('returns true if the agent matches the context agent.', async(): Promise<void> => {
      expect(evaluateAgent('agent', { target: 'target', agent: 'agent' })).toBe(true);
      expect(evaluateAgent('agent', { target: 'target', agent: 'other' })).toBe(false);
    });
  });

  describe('#evaluateClient', (): void => {
    it('returns true if the client matches the context client.', async(): Promise<void> => {
      expect(evaluateClient('client', { target: 'target', client: 'client' })).toBe(true);
      expect(evaluateClient('client', { target: 'target', client: 'other' })).toBe(false);
      expect(evaluateClient('client', { target: 'target' })).toBe(false);
    });
  });

  describe('#evaluateIssuer', (): void => {
    it('returns true if the issuer matches the context issuer.', async(): Promise<void> => {
      expect(evaluateIssuer('issuer', { target: 'target', issuer: 'issuer' })).toBe(true);
      expect(evaluateIssuer('issuer', { target: 'target', issuer: 'other' })).toBe(false);
      expect(evaluateIssuer('issuer', { target: 'target' })).toBe(false);
    });
  });

  describe('#evaluateVc', (): void => {
    it('returns true if there is a VC in the context that matches.', async(): Promise<void> => {
      expect(evaluateVc('vc', { target: 'target', vc: [ 'vc' ]})).toBe(true);
      expect(evaluateVc('vc', { target: 'target', vc: [ 'other' ]})).toBe(false);
      expect(evaluateVc('vc', { target: 'target' })).toBe(false);
    });
  });
});
