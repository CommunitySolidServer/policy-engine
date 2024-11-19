import { createVocabulary } from 'rdf-vocabulary';

export const ACL = createVocabulary(
  'http://www.w3.org/ns/auth/acl#',
  'accessTo',
  'agent',
  'agentClass',
  'agentGroup',
  'AuthenticatedAgent',
  'Authorization',
  'default',
  'mode',

  'Write',
  'Read',
  'Append',
  'Control',
);

export const ACP = createVocabulary(
  'http://www.w3.org/ns/solid/acp#',

  // Used for ACP middleware headers
  'AccessControlResource',
  'grant',
  'attribute',

  // Access Control Resource
  'resource',
  'accessControl',
  'memberAccessControl',

  // Access Control,
  'apply',

  // Policy
  'allow',
  'deny',
  'allOf',
  'anyOf',
  'noneOf',

  // Context
  'Context',
  'target',
  'agent',
  'creator',
  'owner',
  'client',
  'issuer',
  'vc',

  // Matcher types
  'AuthenticatedAgent',
  'CreatorAgent',
  'OwnerAgent',
  'PublicAgent',
  'PublicClient',

  // Grants
  'context',
);

export const ACP_REPORT = createVocabulary(
  'urn:report:acp:',
  'AcpReport',
  'PolicyReport',

  'policyReport',

  'policy',
  'constraintReport',
  'constraint',

  'matcher',
  'success',
);

export const DC = createVocabulary(
  'http://purl.org/dc/terms/',
  'created',
);

export const FOAF = createVocabulary(
  'http://xmlns.com/foaf/0.1/',
  'Agent',
);

export const PERMISSIONS = createVocabulary(
  'urn:report:permissions:',
  'Append',
  'Create',
  'Delete',
  'Modify',
  'Read',
);

export const REPORT = createVocabulary(
  'urn:report:default:',
  'Report',

  'grant',
  'deny',

  'proof',
  'target',
);

export const RDF = createVocabulary(
  'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
  'type',
);

export const VCARD = createVocabulary(
  'http://www.w3.org/2006/vcard/ns#',
  'hasMember',
);

export const WAC_REPORT = createVocabulary(
  'urn:report:wac:',
  'WacAclReport',
  'WacAuthReport',

  'authReport',
  'authorization',
  'subjectReport',
);

export const XSD = createVocabulary(
  'http://www.w3.org/2001/XMLSchema#',
  'boolean',
  'dateTime',
);
