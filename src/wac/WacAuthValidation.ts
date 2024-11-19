import type { WacAuthorization } from './WacAuthorization';

/**
 * A validation of a {@link WacAuthorization}.
 * For each of the fields, this tracks if they were successful and what the reason for the result is.
 */
export interface WacAuthValidation {
  auth: WacAuthorization;
  agent?: { success: boolean; reason?: string };
  agentClass?: { success: boolean; reason?: string };
  agentGroup?: { success: boolean; reason?: string };
}
