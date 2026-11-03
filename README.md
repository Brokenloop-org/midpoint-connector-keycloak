# MidPoint Keycloak Connector

ConnId connector for provisioning [Keycloak](https://keycloak.org) resources from
[MidPoint](https://github.com/Evolveum/midpoint).

## About this fork

This is a hard fork of [openstandia/connector-keycloak](https://github.com/openstandia/connector-keycloak),
which appears to be unmaintained (last release April 2024, multiple unanswered issues
asking about maintenance status, multiple unmerged PRs). The fork brings the connector
forward to current Keycloak versions and adds new object class support.

## Capabilities

| Capability | Status |
|-----------|--------|
| Schema | ✅ |
| Provisioning | ✅ |
| Password | ✅ |
| Activation | ✅ |
| Live Synchronization | ❌ |
| Script execution | ❌ |

## Supported object classes

| Object class | Notes |
|---|---|
| `user` | Full CRUD, password, group membership, custom attributes, role mappings, federated identity links, required actions |
| `group` | Full CRUD with hierarchy via `parentId`, custom attributes, role mappings |
| `client` | Full CRUD including the `type` field added in KC 25 |
| `clientRole` | Full CRUD scoped to a client, composite roles |
| `realmRole` | Full CRUD (added in this fork), composite roles |
| `organization` | Full CRUD with member management (KC 26+; gracefully omitted from schema if the server feature or realm flag is disabled) |

### Role mappings, composites, identity links and required actions

| Object class | Attribute | Multivalued | Value encoding |
|---|---|---|---|
| `user` | `realmRoles` | yes | realm role name |
| `user` | `clientRoles` | yes | `<clientUUID>/<roleName>` |
| `user` | `federatedIdentities` | yes | canonical JSON, see below |
| `user` | `requiredActions` | yes | required action alias (e.g. `UPDATE_PASSWORD`) |
| `group` | `realmRoles` | yes | realm role name |
| `group` | `clientRoles` | yes | `<clientUUID>/<roleName>` |
| `realmRole` | `compositeRealmRoles` | yes | realm role name |
| `realmRole` | `compositeClientRoles` | yes | `<clientUUID>/<roleName>` |
| `clientRole` | `compositeRealmRoles` | yes | realm role name |
| `clientRole` | `compositeClientRoles` | yes | `<clientUUID>/<roleName>` |

Encodings:

- **Realm role**: the plain role name, e.g. `role-a`.
- **Client role**: `<clientUUID>/<roleName>`, where the client UUID is the Keycloak
  internal id of the client (not its `clientId`), e.g. `0b6f.../role-a`.
- **Federated identity**: a JSON object with fixed key order and no whitespace,
  `{"identityProvider":"idp-1","userId":"1234","userName":"alice"}`. `identityProvider`
  and `userId` are required; `userName` defaults to `userId` when omitted on input.

Semantics:

- Only **direct** mappings are read and written. Roles a user inherits through group
  membership or through composites are not expanded.
- All of these attributes except `requiredActions` are **not returned by default**;
  request them explicitly (for example with `attributesToGet` or MidPoint's "fetch"
  option). `requiredActions` is part of the user representation and is returned by default.
- When `allowPartialAttributeValues` is requested, the role, composite and
  `federatedIdentities` attributes are returned as `INCOMPLETE` (without values), as `groups` is.
- Roles listed in `ignoredRoles` (see below) are never read, added or removed by user and
  group role mappings. The list does not apply to composites. For client roles an entry
  matches only the full `<clientUUID>/<roleName>` value.

## Configuration

Options added in this fork, on top of those inherited from upstream:

| Option | Default | Description |
|---|---|---|
| `ignoredRoles` | `default-roles-{realm}`, `offline_access`, `uma_authorization` | Role names that are never read, added or removed by role-mapping operations. `{realm}` is replaced with the target realm name. |
| `logoutOnDisable` | `false` | When `true`, all sessions of a user are terminated when the user is disabled. |
| `userProfileSchemaEnabled` | `false` | When `true`, user attributes declared in the realm's User Profile are added to the `user` schema. Explicitly configured user attributes that are missing from the User Profile are reported with a warning. |

The Keycloak REST client uses a lenient JSON mapper: properties returned by the server
that the admin client does not know about are ignored instead of failing the request.
The admin client (26.0.12) is tested against Keycloak 26.5.7 and 26.8.1.

## Build

Requires JDK 17 (KC 26 admin client requires it) and Maven 3.6+.

```sh
mvn install
```

The connector JAR appears as `target/connector-keycloak-<version>.jar`.

## Testing

```sh
mvn test       # unit tests (no Keycloak required)
mvn verify     # adds integration tests against a live Keycloak
```

Integration tests can be driven by either of two paths:

### Nix (recommended for development)

```sh
nix run .#integration-test    # all-in-one: starts KC, runs tests, stops KC
```

The Nix flake bundles JDK 17, Maven, and Keycloak (no Docker required). Suitable for
local dev and CI runners that have Nix available.

### Docker Compose

```sh
docker compose up -d                  # starts KC 26 on :8090
mvn verify -Dgpg.skip=true            # run tests
docker compose down                   # stop KC
```

KC needs to be reachable at `http://localhost:8090` by default; override with
`-Dkeycloak.url=http://your-kc:8080`.

## Significant changes vs upstream

- **Keycloak admin client upgraded to 26.0.12** (was stuck at 24.0.2), tested against Keycloak 26.5.7 and 26.8.1
- **Java 17 minimum** (required by KC 26)
- **`realmRole` object class** for provisioning realm-level roles
- **`organization` object class** (KC 26+ feature, with graceful detection of server/realm enablement)
- **Role mappings** for users and groups (`realmRoles`, `clientRoles`), direct mappings only
- **Composite roles** on `realmRole` and `clientRole` (`compositeRealmRoles`, `compositeClientRoles`)
- **Federated identity links** on users (`federatedIdentities`)
- **Required actions** on users (`requiredActions`)
- **Optional session logout on disable** (`logoutOnDisable`)
- **User Profile schema**: user attributes derived from the realm User Profile (`userProfileSchemaEnabled`)
- **Built-in attribute names win**: entries in `userAttributes` or `groupAttributes` that collide with an attribute the connector defines itself (for example `requiredActions`, `realmRoles`, `clientRoles`, `federatedIdentities`) are skipped with a warning
- **Lenient JSON mapper** in the REST client: unknown properties in server responses are ignored
- **Client `type` field** (added in KC 25) exposed as a schema attribute
- **ConnId search-contract compliance**: `SearchResultsHandler.handleResult(allResultsReturned=true)` is now signaled correctly, fixing phantom page counts in MidPoint and respecting handler return values for early termination
- **Bug fixes** found by integration tests: Jackson version mismatch (KC 26 group serialization), client search-by-name NPE, password update HTTP 400 against KC 26
- **Test suite**: pure-unit, schema, exception-mapping, and integration tests with full CRUD coverage
- **Group hierarchy**: replaced fragile path-parsing with direct `getParentId()` lookups
- **Removed obsolete profiles**: `midpoint40` and `midpoint44` (incompatible with Java 17)

## License

Licensed under the [Apache License 2.0](LICENSE), inherited from upstream.

Original work © Nomura Research Institute, Ltd.
