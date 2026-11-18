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
| `user` | Full CRUD, password, group membership, custom attributes |
| `group` | Full CRUD with hierarchy via `parentId`, custom attributes |
| `client` | Full CRUD including the `type` field added in KC 25 |
| `clientRole` | Full CRUD scoped to a client |
| `realmRole` | Full CRUD (added in this fork) |
| `organization` | Full CRUD with member management (KC 26+; gracefully omitted from schema if the server feature or realm flag is disabled) |

## Build

Requires JDK 17 (KC 26 admin client requires it) and Maven 3.6+.

```sh
mvn install
```

The connector JAR appears as `target/connector-keycloak-<version>.jar`.

## Testing

```sh
mvn test       # unit tests (200+ tests, no Keycloak required)
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

- **Keycloak admin client upgraded to 26.0.7** (was stuck at 24.0.2)
- **Java 17 minimum** (required by KC 26)
- **`realmRole` object class** for provisioning realm-level roles
- **`organization` object class** (KC 26+ feature, with graceful detection of server/realm enablement)
- **Client `type` field** (added in KC 25) exposed as a schema attribute
- **ConnId search-contract compliance**: `SearchResultsHandler.handleResult(allResultsReturned=true)` is now signaled correctly, fixing phantom page counts in MidPoint and respecting handler return values for early termination
- **Bug fixes** found by integration tests: Jackson version mismatch (KC 26 group serialization), client search-by-name NPE, password update HTTP 400 against KC 26
- **Test suite**: ~200 tests including pure-unit, schema, exception-mapping, and integration tests with full CRUD coverage
- **Group hierarchy**: replaced fragile path-parsing with direct `getParentId()` lookups
- **Removed obsolete profiles**: `midpoint40` and `midpoint44` (incompatible with Java 17)

## License

Licensed under the [Apache License 2.0](LICENSE), inherited from upstream.

Original work © Nomura Research Institute, Ltd.
