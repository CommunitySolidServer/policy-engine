// Interfaces corresponding to the ACP spec. Based on @solid/access-control-policy interfaces.

export interface IriResource {
  readonly iri: string;
}

export interface Context {
  readonly target: string;
  readonly agent?: string;
  readonly issuer?: string;
  readonly client?: string;
  readonly creator?: string[];
  readonly owner?: string[];
  readonly vc?: string[];
}

export interface AccessControlResource extends IriResource {
  readonly resource: string[];
  readonly accessControl: AccessControl[];
  readonly memberAccessControl: AccessControl[];
}

export interface AccessControl extends IriResource {
  readonly policy: Policy[];
}

export interface Policy extends IriResource {
  readonly allOf: Matcher[];
  readonly anyOf: Matcher[];
  readonly noneOf: Matcher[];
  readonly allow: Set<string>;
  readonly deny: Set<string>;
}

export interface Matcher extends IriResource {
  readonly agent: string[];
  readonly client: string[];
  readonly issuer: string[];
  readonly vc: string[];
}
