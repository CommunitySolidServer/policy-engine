import type { AccessChecker } from '../../../../src/wac/access/AccessChecker';
import { UnionAccessChecker } from '../../../../src/wac/access/UnionAccessChecker';

describe('UnionAccessChecker', (): void => {
  let handlers: jest.Mocked<AccessChecker>[];
  let checker: UnionAccessChecker;

  beforeEach(async(): Promise<void> => {
    handlers = [
      {
        canHandle: jest.fn(),
        handle: jest.fn().mockResolvedValue({
          agent: { success: true, reason: 'http://example.com/agent' },
          agentClass: { success: true, reason: 'http://example.com/agentClass' },
        }),
      } satisfies Partial<AccessChecker> as any,
      {
        canHandle: jest.fn(),
        handle: jest.fn().mockResolvedValue({
          agent: { success: true, reason: 'http://example.com/agent2' },
          agentGroup: { success: true, reason: 'http://example.com/agentGroup' },
        }),
      } satisfies Partial<AccessChecker> as any,
    ];

    checker = new UnionAccessChecker(handlers);
  });

  it('returns a union of the results.', async(): Promise<void> => {
    await expect(checker.handle({ credentials: {}, auth: {} as any })).resolves.toEqual({
      agent: { success: true, reason: 'http://example.com/agent' },
      agentGroup: { success: true, reason: 'http://example.com/agentGroup' },
      agentClass: { success: true, reason: 'http://example.com/agentClass' },
    });
  });
});
