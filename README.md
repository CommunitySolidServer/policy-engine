# Solid Policy Engine

[![npm version](https://img.shields.io/npm/v/%40solidlab%2Fpolicy-engine)](https://www.npmjs.com/package/@solidlab/policy-engine)

This package provides support for both [Web Access Control](https://solidproject.org/TR/2021/wac-20210711)(WAC)
and [Access Control Policies](https://solid.github.io/authorization-panel/acp-specification/)(ACP) authorization.

## Main Components

### AuthorizationManager

This is the minimal interface of external functions a policy engine needs to be able to determine a result.

Due to the nature of Solid, an engine needs a way to find the parent container of a resource.
This is done through the `getParent` function,
which should return the identifier of the parent container,
or `undefined` if the input is a root storage container.

Besides that the engine also needs a way to receive the relevant authorization data for a resource.
In the case of WAC this would be the contents of the corresponding ACL resource.
The `getAuthorizationData` should return this data if it exists,
and `undefined` otherwise.

This package does not provide an implementation of this interface as this depends on the Solid server implementation.
It is recommended to have some form of caching for `getAuthorizationData`.

### PolicyEngine

This is the core interface for the package.
`getPermissions` is used to determine the permissions,
while `getPermissionsWithReport` does the same but also generates an RDF report indicating how the result was achieved.
The contents of the report depend on the type of authorization,
as this will differ between WAC and ACP.

### AclPermissionsEngine

An implementation of `PolicyEngine` that converts ACL permissions to more generic permissions.
It takes into account how ACL permissions have to be interpreted.
Specifically applies the following three rules:

* `acl:Write` implies `acl:Append`.
* To create a new resource you need `acl:Write` on the target, and `acl:Append` on the parent.
* To delete a resource, you need `acl:Write` on the target, and `acl:Write` on the parent.

## Web Access Control

These are the classes and interfaces specifically for WAC.

### WacRepository / ManagedWacRepository

The `WacRepository` interface is used to determine the WAC authorization objects
that are relevant when determining permissions for the given target.
The `ManagedWacRepository` is an actual implementation that makes use of a `AuthorizationManager`
to achieve this goal.

### WacPolicyEngine

The `WacPolicyEngine` is an implementation of `PolicyEngine` for WAC authorization.
It requires a `WacRepository` to do the initial filtering.
It then uses an `AccessChecker` to determine which of these authorizations are valid
and generates its result based on that.

### Access Checker

There are several ways a WAC authorization might be valid:
the credentials could have a matching agent,
the agent could be part of the correct class,
or the agent could be part of a matching group.

For each of those there is a separate access checker,
and the result of these can then be combined using a `UnionAccessChecker`.
In practice this means you generally want to define your `AccessChecker` as follows:

```ts
const accessChecker = new UnionAccessChecker([
  new AgentAccessChecker(),
  new AgentClassAccessChecker(),
  new AgentGroupAccessChecker(),
])
```

## Access Control Policies

These are the classes and interfaces specifically for ACP.
These work similarly to the WAC classes.

### AcpRepository / ManagedAcpRepository

The `AcpRepository` interface is used to determine the ACP authorization objects
that are relevant when determining permissions for the given target.
The `ManagedAcpRepository` is an actual implementation that makes use of a `AuthorizationManager`
to achieve this goal.

### AcpPolicyEngine

The `AcpPolicyEngine` is an implementation of `PolicyEngine` for ACP authorization.
It requires a `AcpRepository` to do the initial filtering.

## Example

Below is an example of how these classes can be set up and used to generate a permission report.
The example focuses on WAC, but would be quite similar for ACP.

```ts
// The manager is an external object, dependent on the server implementation
async function generateReport(
  target: string,
  credentials: Credentials,
  manager: AuthorizationManager,
  permissions?: string[]
): Promise<PermissionReport> {
  // The AccessChecker determines if WAC authorizations are valid
  const accessChecker = new UnionAccessChecker([
    new AgentAccessChecker(),
    new AgentClassAccessChecker(),
    new AgentGroupAccessChecker(),
  ]);

  // The engine needs a repository to get the authorizations
  const wacEngine = new WacPolicyEngine(accessChecker, new ManagedWacRepository(wacManager));
  
  // This engine will make sure the ACL permissions get interpreted correctly
  const engine = new AclPermissionsEngine(wacEngine, manager);

  // The engine can then generate a report for the given target and credentials
  const report = await engine.getPermissionsWithReport(target, credentials, permissions);
}
```

## Components.js

The config folder contains [Components.js](https://github.com/LinkedSoftwareDependencies/Components.js/) configurations
which can be used in your project to add the necessary authorization components.
`acp.json` contains the necessary parts for ACP authorization,
and `wac.json` those for WAC.

urn:solidlab:policy-engine:AuthorizationManager
