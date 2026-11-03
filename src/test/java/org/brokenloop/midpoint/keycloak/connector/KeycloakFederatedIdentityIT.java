package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;

import java.util.*;
import java.util.stream.Collectors;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakFederatedIdentityIT extends AbstractKeycloakIT {

    static final String REALM = "it-fed";
    static KeycloakConnector connector;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        try (Keycloak admin = adminClient()) {
            IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
            idp.setAlias("idp-1");
            idp.setProviderId("saml");
            idp.setEnabled(true);
            idp.setConfig(new HashMap<>(Map.of(
                    "singleSignOnServiceUrl", "https://idp.example.com/sso",
                    "entityId", "https://idp.example.com/entity")));
            admin.realm(REALM).identityProviders().create(idp).close();
        }
        connector = newConnector(REALM);
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    private static String json(String userId) {
        return "{\"identityProvider\":\"idp-1\",\"userId\":\"" + userId + "\",\"userName\":\"" + userId + "\"}";
    }

    private Uid createUser(String name, Attribute... extra) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        attrs.addAll(Arrays.asList(extra));
        return connector.create(USER_OBJECT_CLASS, attrs, null);
    }

    private List<FederatedIdentityRepresentation> links(Uid uid) {
        try (Keycloak admin = adminClient()) {
            return admin.realm(REALM).users().get(uid.getUidValue()).getFederatedIdentity();
        }
    }

    private void update(Uid uid, AttributeDelta... deltas) {
        connector.updateDelta(USER_OBJECT_CLASS, uid, new HashSet<>(Arrays.asList(deltas)), null);
    }

    @Test
    void createUserWithLink() {
        Uid uid = createUser("alice-create", AttributeBuilder.build("federatedIdentities", json("alice@example.com")));
        List<FederatedIdentityRepresentation> l = links(uid);
        assertEquals(1, l.size());
        assertEquals("idp-1", l.get(0).getIdentityProvider());
        assertEquals("alice@example.com", l.get(0).getUserId());
    }

    @Test
    void readReturnsCanonicalJson() {
        Uid uid = createUser("alice-read", AttributeBuilder.build("federatedIdentities", json("Alice@example.com")));
        ConnectorObject o = searchByUidWithAttrs(connector, USER_OBJECT_CLASS, uid, "federatedIdentities");
        Set<String> values = o.getAttributeByName("federatedIdentities").getValue().stream()
                .map(String::valueOf).collect(Collectors.toSet());
        assertEquals(Set.of(json("Alice@example.com")), values);
        assertNull(searchByUid(connector, USER_OBJECT_CLASS, uid).getAttributeByName("federatedIdentities"));
    }

    @Test
    void addLinkToExistingUser() {
        Uid uid = createUser("alice-add");
        update(uid, AttributeDeltaBuilder.build("federatedIdentities", List.of(json("alice@example.com")), List.of()));
        assertEquals(1, links(uid).size());
        assertEquals("alice@example.com", links(uid).get(0).getUserId());
    }

    @Test
    void removeLink() {
        Uid uid = createUser("alice-remove", AttributeBuilder.build("federatedIdentities", json("alice@example.com")));
        update(uid, AttributeDeltaBuilder.build("federatedIdentities", List.of(), List.of(json("alice@example.com"))));
        assertTrue(links(uid).isEmpty());
    }

    @Test
    void replaceLinkForSameAlias() {
        Uid uid = createUser("alice-replace", AttributeBuilder.build("federatedIdentities", json("a@example.com")));
        update(uid, AttributeDeltaBuilder.build("federatedIdentities",
                List.of(json("A@example.com")), List.of(json("a@example.com"))));
        List<FederatedIdentityRepresentation> l = links(uid);
        assertEquals(1, l.size());
        assertEquals("A@example.com", l.get(0).getUserId());

        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("federatedIdentities");
        b.addValueToReplace(json("b@example.com"));
        update(uid, b.build());
        l = links(uid);
        assertEquals(1, l.size());
        assertEquals("b@example.com", l.get(0).getUserId());
    }

    @Test
    void addWithoutRemoveReplacesExistingAlias() {
        Uid uid = createUser("alice-addonly", AttributeBuilder.build("federatedIdentities", json("a@example.com")));
        update(uid, AttributeDeltaBuilder.build("federatedIdentities", List.of(json("A@example.com")), List.of()));
        assertEquals("A@example.com", links(uid).get(0).getUserId());
    }

    @Test
    void unknownAliasFails() {
        String bad = "{\"identityProvider\":\"nope\",\"userId\":\"x\"}";
        assertThrows(InvalidAttributeValueException.class,
                () -> createUser("alice-bad", AttributeBuilder.build("federatedIdentities", bad)));
        assertNull(searchByNameOrNull("alice-bad"));

        Uid uid = createUser("alice-bad-update");
        assertThrows(InvalidAttributeValueException.class,
                () -> update(uid, AttributeDeltaBuilder.build("federatedIdentities", List.of(bad), List.of())));
    }

    private static String json(String idp, String userId) {
        return "{\"identityProvider\":\"" + idp + "\",\"userId\":\"" + userId + "\",\"userName\":\"" + userId + "\"}";
    }

    @Test
    void removeStaleValueKeepsCurrentLink() {
        Uid uid = createUser("alice-stale", AttributeBuilder.build("federatedIdentities", json("new")));
        update(uid, AttributeDeltaBuilder.build("federatedIdentities", List.of(), List.of(json("old"))));
        List<FederatedIdentityRepresentation> l = links(uid);
        assertEquals(1, l.size());
        assertEquals("new", l.get(0).getUserId());
    }

    @Test
    void duplicateAliasOnCreateRejected() {
        assertThrows(InvalidAttributeValueException.class, () -> createUser("alice-dup-create",
                AttributeBuilder.build("federatedIdentities", json("a"), json("b"))));
        assertNull(searchByNameOrNull("alice-dup-create"));
    }

    @Test
    void duplicateAliasOnUpdateRejected() {
        Uid uid = createUser("alice-dup-update", AttributeBuilder.build("federatedIdentities", json("keep")));
        assertThrows(InvalidAttributeValueException.class, () -> update(uid,
                AttributeDeltaBuilder.build("federatedIdentities", List.of(json("a"), json("b")), List.of())));
        List<FederatedIdentityRepresentation> l = links(uid);
        assertEquals(1, l.size());
        assertEquals("keep", l.get(0).getUserId());
    }

    private ConnectorObject searchByNameOrNull(String name) {
        List<ConnectorObject> all = searchAll(connector, USER_OBJECT_CLASS);
        return all.stream().filter(o -> name.equals(o.getName().getNameValue())).findFirst().orElse(null);
    }
}
