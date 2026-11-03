package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.*;
import java.util.stream.Collectors;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakUserRoleMappingIT extends AbstractKeycloakIT {

    static final String REALM = "it-user-roles";
    static KeycloakConnector connector;
    static String app1Uuid;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        try (Keycloak admin = adminClient()) {
            var roles = admin.realm(REALM).roles();
            roles.create(role("role-a"));
            roles.create(role("role-b"));
            roles.create(role("role-c"));
            roles.get("role-c").addComposites(List.of(roles.get("role-a").toRepresentation()));

            ClientRepresentation client = new ClientRepresentation();
            client.setClientId("app-1");
            admin.realm(REALM).clients().create(client).close();
            app1Uuid = admin.realm(REALM).clients().findByClientId("app-1").get(0).getId();
            var clientRoles = admin.realm(REALM).clients().get(app1Uuid).roles();
            clientRoles.create(role("cr-1"));
            clientRoles.create(role("cr-2"));
        }
        connector = newConnector(REALM);
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    private static RoleRepresentation role(String name) {
        RoleRepresentation r = new RoleRepresentation();
        r.setName(name);
        return r;
    }

    private Uid createUser(String name, Attribute... extra) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        attrs.addAll(Arrays.asList(extra));
        return connector.create(USER_OBJECT_CLASS, attrs, null);
    }

    private Set<String> directRealm(Uid uid) {
        try (Keycloak admin = adminClient()) {
            return admin.realm(REALM).users().get(uid.getUidValue()).roles().realmLevel().listAll()
                    .stream().map(RoleRepresentation::getName).collect(Collectors.toSet());
        }
    }

    private Set<String> directClient(Uid uid) {
        try (Keycloak admin = adminClient()) {
            return admin.realm(REALM).users().get(uid.getUidValue()).roles().clientLevel(app1Uuid).listAll()
                    .stream().map(RoleRepresentation::getName).collect(Collectors.toSet());
        }
    }

    private Set<String> values(ConnectorObject o, String attr) {
        Attribute a = o.getAttributeByName(attr);
        if (a == null || a.getValue() == null) return Set.of();
        return a.getValue().stream().map(String::valueOf).collect(Collectors.toSet());
    }

    private void update(Uid uid, AttributeDelta... deltas) {
        connector.updateDelta(USER_OBJECT_CLASS, uid, new HashSet<>(Arrays.asList(deltas)), null);
    }

    @Test
    void createWithRealmAndClientRoles() {
        Uid uid = createUser("alice-create",
                AttributeBuilder.build("realmRoles", "role-a"),
                AttributeBuilder.build("clientRoles", app1Uuid + "/cr-1"));
        assertEquals(Set.of("role-a", "default-roles-" + REALM), directRealm(uid));
        assertEquals(Set.of("cr-1"), directClient(uid));
    }

    @Test
    void readReturnsDirectOnlyAndHidesIgnored() {
        Uid uid = createUser("alice-read", AttributeBuilder.build("realmRoles", "role-c"));
        ConnectorObject o = searchByUidWithAttrs(connector, USER_OBJECT_CLASS, uid, "realmRoles", "clientRoles");
        assertEquals(Set.of("role-c"), values(o, "realmRoles"));
    }

    @Test
    void notReturnedWithoutAttributesToGet() {
        Uid uid = createUser("alice-plain", AttributeBuilder.build("realmRoles", "role-a"));
        ConnectorObject o = searchByUid(connector, USER_OBJECT_CLASS, uid);
        assertNull(o.getAttributeByName("realmRoles"));
        assertNull(o.getAttributeByName("clientRoles"));
    }

    @Test
    void addAndRemoveDeltas() {
        Uid uid = createUser("alice-delta", AttributeBuilder.build("realmRoles", "role-a"));
        update(uid, AttributeDeltaBuilder.build("realmRoles", List.of("role-b"), List.of("role-a")));
        ConnectorObject o = searchByUidWithAttrs(connector, USER_OBJECT_CLASS, uid, "realmRoles");
        assertEquals(Set.of("role-b"), values(o, "realmRoles"));
    }

    @Test
    void replaceDelta() {
        Uid uid = createUser("alice-replace", AttributeBuilder.build("realmRoles", "role-b"));
        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("realmRoles");
        b.addValueToReplace("role-a");
        update(uid, b.build());
        assertEquals(Set.of("role-a", "default-roles-" + REALM), directRealm(uid));
    }

    @Test
    void addUnknownRealmRoleFails() {
        Uid uid = createUser("alice-unknown");
        InvalidAttributeValueException e = assertThrows(InvalidAttributeValueException.class,
                () -> update(uid, AttributeDeltaBuilder.build("realmRoles", List.of("nope"), List.of())));
        assertTrue(e.getMessage().contains("nope"));
    }

    @Test
    void removeAbsentRoleIsNoop() {
        Uid uid = createUser("alice-noop", AttributeBuilder.build("realmRoles", "role-a"));
        update(uid, AttributeDeltaBuilder.build("realmRoles", List.of(), List.of("role-b")));
        assertEquals(Set.of("role-a", "default-roles-" + REALM), directRealm(uid));
    }

    @Test
    void clientRoleAddRemove() {
        Uid uid = createUser("alice-client", AttributeBuilder.build("clientRoles", app1Uuid + "/cr-1"));
        update(uid, AttributeDeltaBuilder.build("clientRoles",
                List.of(app1Uuid + "/cr-2"), List.of(app1Uuid + "/cr-1")));
        assertEquals(Set.of("cr-2"), directClient(uid));
        ConnectorObject o = searchByUidWithAttrs(connector, USER_OBJECT_CLASS, uid, "clientRoles");
        assertEquals(Set.of(app1Uuid + "/cr-2"), values(o, "clientRoles"));
    }
}
