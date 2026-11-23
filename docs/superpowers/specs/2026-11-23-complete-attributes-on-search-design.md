# Complete user attributes on search (opt-in)

## Intent
midPoint reads users with `ALLOW_PARTIAL_ATTRIBUTE_VALUES`. The connector then returns
`groups`, `realmRoles`, `clientRoles` and `federatedIdentities` as INCOMPLETE with no values.
Logic that has to see one of them during a search, such as an object type classified by a
realm role, sees nothing. Reading the shadow from inside classification does not help,
because it re-enters classification. The connector has to be able to return the values itself.

## Goals / non-goals
- Goal: an opt-in, per-attribute way to return real values for these user attributes even
  when partial values are allowed.
- Non-goal: changing the defaults. With the property empty, behaviour is byte-for-byte unchanged.
- Non-goal: group, realm-role or client-role object classes (their composite and role-mapping
  attributes stay INCOMPLETE).
- Anti-goal: hidden cost. The README must state the extra Keycloak call per user and attribute.

## Approaches
1. A boolean for realm roles only (`completeRealmRolesOnSearch`). Smallest, but each future need
   adds another property.
2. **Chosen:** a multi-valued property listing which user attributes to complete. Costs about the
   same to build and covers `groups`, `clientRoles` and `federatedIdentities` when they are needed later.
3. Complete everything whenever partial values are requested. Rejected: it defeats the purpose of
   partial values and multiplies the cost of imports.

## Design
- New configuration property `completeAttributesOnSearch` (`String[]`, order 24, default empty).
  Allowed values are `groups`, `realmRoles`, `clientRoles` and `federatedIdentities`.
  `validate()` rejects any other name with a `ConfigurationException` (blank entries are ignored).
- It applies to user reads with partial values allowed: search, get by uid and get by name all go through
  `KeycloakAdminRESTUser.toConnectorObject`.
- For each listed attribute, when partial values are allowed and `attributesToGet` is null or
  contains the attribute: read the values exactly as the non-partial path does (same Keycloak
  calls, same `ignoredRoles` filtering for roles, same value formats) and return them as complete.
- If `attributesToGet` is non-null and leaves the attribute out, keep today's INCOMPLETE marker.
- Attributes that are not listed keep today's behaviour.
- When both `realmRoles` and `clientRoles` are listed, each is read with its own call, as the
  non-partial path does today (builder's call whether to share one `getAll()` call).

## Tests and docs
- Unit: property default (empty), set/get, validation of unknown names.
- IT (`KeycloakPartialValuesIT`, Keycloak 26.5.7 / 26.7.4 / 26.8.1 in CI): with `realmRoles` listed,
  a partial search returns the direct realm roles of the user (ignored roles filtered, values complete),
  while unlisted attributes stay INCOMPLETE; the default stays INCOMPLETE for all four. Cover each
  allowed attribute at least once.
- README: a property row with the cost (one extra Keycloak call per user returned, per listed attribute)
  and a CHANGELOG/feature line if the README keeps one.

## Release
As for 2.0.0 (#3, #4): this PR also sets `pom.xml` to `2.0.1` and the README version references.
After it merges, tag `v2.0.1` on main (triggers `release.yml`), then a follow-up PR moves to
`2.0.2-SNAPSHOT`. Tagging and the follow-up need the user's go-ahead.
Public repo: generic wording only. Maven runs with `-s m2-settings.xml`.
