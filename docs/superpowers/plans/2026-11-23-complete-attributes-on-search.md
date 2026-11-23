# Complete User Attributes on Search Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the opt-in `completeAttributesOnSearch` configuration property, which makes user reads return real values for the listed association-like attributes even when partial values are allowed. Release it as 2.0.1.

**Architecture:** `KeycloakConfiguration` gains a validated `String[]` property and a resolved `Set<String>` accessor. `KeycloakAdminRESTUser.toConnectorObject` (used by search, get-by-uid and get-by-name) asks that set whether each partial-mode attribute should be completed; if so, it uses the existing non-partial read code, otherwise it keeps today's INCOMPLETE marker.

**Tech Stack:** Java 17, ConnId, Keycloak admin client, JUnit 5, Maven (surefire for unit tests, failsafe for `*IT` against a live Keycloak at `http://localhost:8090`).

**Spec:** `docs/superpowers/specs/2026-11-23-complete-attributes-on-search-design.md`

## Global Constraints

- Property name `completeAttributesOnSearch`, type `String[]`, `@ConfigurationProperty(order = 24)`, default empty.
- Allowed values, exactly: `groups`, `realmRoles`, `clientRoles`, `federatedIdentities`. Unknown names → `ConfigurationException` from `validate()`. Null/blank entries are ignored.
- An empty property means behaviour is unchanged.
- Only the user object class changes. Group, realm-role and client-role object classes stay INCOMPLETE.
- Public repo: generic wording only. No organisation- or deployment-specific names in code, tests, README or commits.
- No references to Claude in commit messages (user rule). Commit as the existing git identity.
- Integration tests run against Keycloak 26.5.7 / 26.7.4 / 26.8.1 in CI (`.github/workflows/ci.yml`). Locally, use `docker compose up -d` (26.8.1).

## Review Focus

1. Listed attribute + partial + `attributesToGet` containing other attributes but not this one → still INCOMPLETE, and no Keycloak call is made. (Test in Task 2.)
2. `realmRoles` listed → `ignoredRoles` (e.g. `default-roles-{realm}`) are filtered out of the completed values, same as the non-partial read. (Test in Task 2.)
3. Get-by-uid with partial values (not just search) also completes the attribute. (Test in Task 2.)
4. Entries with surrounding whitespace or mixed case (`" realmRoles"`, `"RealmRoles"`): trim whitespace; names are case-sensitive, so `RealmRoles` is rejected by `validate()` with a message listing the allowed names. (Test in Task 1.)
5. A user with no mappings at all → completed attribute present with an empty value list and complete status (not INCOMPLETE, not missing). (Test in Task 2.)

---

### Task 1: Configuration property and validation

**Files:**
- Modify: `src/main/java/org/brokenloop/midpoint/keycloak/connector/KeycloakConfiguration.java` (field near line 59; property after `isUserProfileSchemaEnabled`, ~line 427; `validate()`, ~line 430)
- Test: `src/test/java/org/brokenloop/midpoint/keycloak/connector/KeycloakConfigurationTest.java`

**Interfaces:**
- Produces:
  - `public String[] getCompleteAttributesOnSearch()` / `public void setCompleteAttributesOnSearch(String[] v)`: defensive copies, like `ignoredRoles`.
  - `public Set<String> completeAttributesOnSearchResolved()`: unmodifiable set of trimmed, non-blank entries. Never null.
  - `public static final Set<String> COMPLETABLE_USER_ATTRIBUTES = Set.of("groups", "realmRoles", "clientRoles", "federatedIdentities")` on `KeycloakConfiguration`.

- [ ] **Step 1: Write the failing tests** in `KeycloakConfigurationTest` (build a valid config with the existing helper or username/password pattern used by `validate_usernameAndPassword_succeeds`):

```java
@Test void completeAttributesOnSearchDefaultsToEmpty() {
    KeycloakConfiguration c = new KeycloakConfiguration();
    assertEquals(0, c.getCompleteAttributesOnSearch().length);
    assertTrue(c.completeAttributesOnSearchResolved().isEmpty());
}
@Test void completeAttributesOnSearchTrimsAndDropsBlanks() {
    KeycloakConfiguration c = new KeycloakConfiguration();
    c.setCompleteAttributesOnSearch(new String[]{" realmRoles ", "", null, "groups"});
    assertEquals(Set.of("realmRoles", "groups"), c.completeAttributesOnSearchResolved());
}
@Test void completeAttributesOnSearchIsCopiedInAndOut() {
    String[] in = {"realmRoles"};
    KeycloakConfiguration c = new KeycloakConfiguration();
    c.setCompleteAttributesOnSearch(in);
    in[0] = "groups";
    assertArrayEquals(new String[]{"realmRoles"}, c.getCompleteAttributesOnSearch());
}
@Test void validate_allCompletableAttributes_succeeds() {
    // valid credentials + all four names → no exception
}
@Test void validate_unknownCompletableAttribute_throws() {
    // valid credentials + {"realmRoles", "RealmRoles"} → ConfigurationException
    // message contains "RealmRoles" and "groups, realmRoles, clientRoles, federatedIdentities"
}
```

- [ ] **Step 2: Run and see them fail**

Run: `mvn -q test -Dtest=KeycloakConfigurationTest`
Expected: compilation failure (methods not defined).

- [ ] **Step 3: Implement** the field (`private String[] completeAttributesOnSearch = {};`), getter/setter, resolved accessor, constant, and a `@ConfigurationProperty(order = 24, displayMessageKey = "Complete Attributes On Search", helpMessageKey = "User attributes (groups, realmRoles, clientRoles, federatedIdentities) returned with their values even when partial attribute values are allowed. Each listed attribute costs one extra Keycloak call per user returned. Default is none.", required = false, confidential = false)` on the getter. In `validate()`, after the credential check, reject any resolved entry that isn't in `COMPLETABLE_USER_ATTRIBUTES`, with the message `"Unknown attribute in completeAttributesOnSearch: <name>. Allowed: groups, realmRoles, clientRoles, federatedIdentities"`. Use a fixed-order string literal for "Allowed", because `Set.of` iteration order is unspecified.

- [ ] **Step 4: Run and see them pass**

Run: `mvn -q test -Dtest=KeycloakConfigurationTest`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/brokenloop/midpoint/keycloak/connector/KeycloakConfiguration.java src/test/java/org/brokenloop/midpoint/keycloak/connector/KeycloakConfigurationTest.java
git commit -m "Add completeAttributesOnSearch configuration property"
```

### Task 2: Complete listed user attributes on partial reads

**Files:**
- Modify: `src/main/java/org/brokenloop/midpoint/keycloak/connector/rest/KeycloakAdminRESTUser.java:595-707` (`toConnectorObject`, `addRoleMappings`, `addFederatedIdentities`)
- Test: `src/test/java/org/brokenloop/midpoint/keycloak/connector/KeycloakPartialValuesIT.java`

**Interfaces:**
- Consumes: `configuration.completeAttributesOnSearchResolved()` from Task 1.
- Produces: `private boolean completeOnPartial(String attrName, Set<String> attributesToGet)` in `KeycloakAdminRESTUser`. It returns `configuration.completeAttributesOnSearchResolved().contains(attrName) && (attributesToGet == null || attributesToGet.contains(attrName))`.

Behaviour per attribute (`groups`, `realmRoles`, `clientRoles`, `federatedIdentities`) when `allowPartialAttributeValues` is true:
- `completeOnPartial(...)` true → read the values with the code the non-partial branch already uses and add a normal (complete) attribute: group ids for `groups`, `RoleMappingOps.readRealm/readClient` with `ignoredRolesResolved()`, `FederatedIdentityCodec::format` values. Factor each read into a small private method shared by both branches, so the read isn't duplicated.
- Otherwise → today's INCOMPLETE marker, unchanged.
Non-partial behaviour stays exactly as it is.

- [ ] **Step 1: Write the failing ITs** in `KeycloakPartialValuesIT`. Setup additions: assign realm roles `role-a` to `alice`, client role `cr-1` to `alice`, group `group-1` membership, and a federated identity link `idp-1` (userId `ext-alice`, userName `alice-ext`). Create user `bob` with no mappings. Store alice's uid. Add a helper `KeycloakConnector connectorCompleting(String... attrs)` that uses `buildConfiguration(REALM)`, calls `setCompleteAttributesOnSearch(attrs)` and `init`s (dispose in a try/finally or `@AfterAll`). Tests:

```java
@Test void listedRealmRolesAreCompleteOnPartialSearch() {
    // connectorCompleting("realmRoles"); search users with optionsWithPartialValues(); alice:
    // realmRoles completeness COMPLETE, values == ["role-a"] (default-roles-it-partial filtered out)
    // clientRoles, groups, federatedIdentities still INCOMPLETE with no values
}
@Test void eachCompletableAttributeIsCompleteWhenListed() {
    // connectorCompleting("groups","realmRoles","clientRoles","federatedIdentities"); alice:
    // groups == [group-1 id], realmRoles == ["role-a"], clientRoles == ["<app-1 uuid>/cr-1"],
    // federatedIdentities == [FederatedIdentityCodec format of idp-1/ext-alice/alice-ext]; all COMPLETE
}
@Test void listedAttributeIsCompleteOnPartialGetByUid() {
    // connectorCompleting("realmRoles"); executeQuery with EqualsFilter(Uid) + partial options → realmRoles == ["role-a"], COMPLETE
}
@Test void listedAttributeLeftOutOfAttributesToGetStaysIncomplete() {
    // connectorCompleting("realmRoles"); options partial + setAttributesToGet("email") → realmRoles INCOMPLETE, no values
}
@Test void listedAttributeOnUserWithoutMappingsIsEmptyAndComplete() {
    // connectorCompleting("realmRoles","federatedIdentities"); bob: both present, COMPLETE, empty
}
```

Change the existing `userAssociationsAreIncomplete` to also cover `groups`; it keeps the default (empty) connector. Adding mappings to alice must not break the existing INCOMPLETE assertions.

- [ ] **Step 2: Run and see them fail** (needs Keycloak: `docker compose up -d`, wait until healthy)

Run: `mvn -q verify -Dit.test=KeycloakPartialValuesIT -Dtest=NoSuchTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: the new tests fail (attributes INCOMPLETE). The existing four pass.

- [ ] **Step 3: Implement** `completeOnPartial` and the branch changes described above in `KeycloakAdminRESTUser`.

- [ ] **Step 4: Run and see them pass**

Same command. Expected: all `KeycloakPartialValuesIT` tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/org/brokenloop/midpoint/keycloak/connector/rest/KeycloakAdminRESTUser.java src/test/java/org/brokenloop/midpoint/keycloak/connector/KeycloakPartialValuesIT.java
git commit -m "Return listed user attributes complete on partial reads"
```

### Task 3: README and 2.0.1 version

**Files:**
- Modify: `README.md` (configuration table after the `userProfileSchemaEnabled` row, ~line 91; feature list ~line 147)
- Modify: `pom.xml:15` (`2.0.1-SNAPSHOT` → `2.0.1`)

- [ ] **Step 1: README row:** `| `completeAttributesOnSearch` | (none) | User attributes returned with their values even when midPoint allows partial attribute values (by default `groups`, `realmRoles`, `clientRoles` and `federatedIdentities` come back as incomplete without values). Allowed: `groups`, `realmRoles`, `clientRoles`, `federatedIdentities`. Each listed attribute costs one extra Keycloak call per user returned, so a search of N users makes up to N extra calls per attribute. Use it when midPoint logic must see the value during a search, e.g. object type classification by realm role. |`. Add a feature bullet: `- **Opt-in complete values on partial reads** (`completeAttributesOnSearch`)`.

- [ ] **Step 2: Bump** `pom.xml` project version to `2.0.1`.

- [ ] **Step 3: Full check**

Run: `mvn -B verify -Dgpg.skip=true -Dmaven.javadoc.skip=true -Dmaven.source.skip=true -Dassembly.skipAssembly=true -Dkeycloak.url=http://localhost:8090 -Dkeycloak.expectedVersion=26.8.1`
Expected: BUILD SUCCESS, with all unit tests and ITs passing.

- [ ] **Step 4: Commit**

```bash
git add README.md pom.xml
git commit -m "Release 2.0.1: completeAttributesOnSearch"
```

After merge (user's go-ahead, not part of this branch): tag `v2.0.1` on main, then a PR moving to `2.0.2-SNAPSHOT`.
