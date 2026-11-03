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

import static org.brokenloop.midpoint.keycloak.connector.KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakCompositeRoleIT extends AbstractKeycloakIT {

    static final String REALM = "it-composites";
    static KeycloakConnector connector;
    static String app1Uuid;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        try (Keycloak admin = adminClient()) {
            var roles = admin.realm(REALM).roles();
            for (String n : new String[]{"role-a", "role-b", "role-c"}) {
                roles.create(role(n));
            }
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

    private Uid createRealmRole(String name, Attribute... extra) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        attrs.addAll(Arrays.asList(extra));
        return connector.create(REALM_ROLE_OBJECT_CLASS, attrs, null);
    }

    private Uid createClientRole(String name, Attribute... extra) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(app1Uuid + "/" + name));
        attrs.addAll(Arrays.asList(extra));
        return connector.create(CLIENT_ROLE_OBJECT_CLASS, attrs, null);
    }

    private Set<String> values(ConnectorObject o, String attr) {
        Attribute a = o.getAttributeByName(attr);
        if (a == null || a.getValue() == null) return Set.of();
        return a.getValue().stream().map(String::valueOf).collect(Collectors.toSet());
    }

    private ConnectorObject read(ObjectClass oc, Uid uid) {
        return searchByUidWithAttrs(connector, oc, uid, "compositeRealmRoles", "compositeClientRoles");
    }

    private void update(ObjectClass oc, Uid uid, AttributeDelta... deltas) {
        connector.updateDelta(oc, uid, new HashSet<>(Arrays.asList(deltas)), null);
    }

    @Test
    void realmRoleWithRealmChildren() {
        Uid uid = createRealmRole("parent-1", AttributeBuilder.build("compositeRealmRoles", "role-a", "role-b"));
        ConnectorObject o = read(REALM_ROLE_OBJECT_CLASS, uid);
        assertEquals(Set.of("role-a", "role-b"), values(o, "compositeRealmRoles"));
        assertEquals(Set.of(), values(o, "compositeClientRoles"));
    }

    @Test
    void realmRoleWithClientChildren() {
        Uid uid = createRealmRole("parent-2", AttributeBuilder.build("compositeClientRoles", app1Uuid + "/cr-1"));
        ConnectorObject o = read(REALM_ROLE_OBJECT_CLASS, uid);
        assertEquals(Set.of(app1Uuid + "/cr-1"), values(o, "compositeClientRoles"));
        assertEquals(Set.of(), values(o, "compositeRealmRoles"));
    }

    @Test
    void clientRoleWithRealmChildren() {
        Uid uid = createClientRole("parent-3",
                AttributeBuilder.build("compositeRealmRoles", "role-a"),
                AttributeBuilder.build("compositeClientRoles", app1Uuid + "/cr-2"));
        ConnectorObject o = read(CLIENT_ROLE_OBJECT_CLASS, uid);
        assertEquals(Set.of("role-a"), values(o, "compositeRealmRoles"));
        assertEquals(Set.of(app1Uuid + "/cr-2"), values(o, "compositeClientRoles"));
    }

    @Test
    void notReturnedWithoutAttributesToGet() {
        Uid uid = createRealmRole("parent-plain", AttributeBuilder.build("compositeRealmRoles", "role-a"));
        ConnectorObject o = searchByUid(connector, REALM_ROLE_OBJECT_CLASS, uid);
        assertNull(o.getAttributeByName("compositeRealmRoles"));
        assertNull(o.getAttributeByName("compositeClientRoles"));
    }

    @Test
    void readReturnsOnlyFirstLevel() {
        Uid c = createRealmRole("lvl-c");
        Uid b = createRealmRole("lvl-b", AttributeBuilder.build("compositeRealmRoles", "lvl-c"));
        Uid a = createRealmRole("lvl-a", AttributeBuilder.build("compositeRealmRoles", "lvl-b"));
        assertNotNull(c);
        assertNotNull(b);
        assertEquals(Set.of("lvl-b"), values(read(REALM_ROLE_OBJECT_CLASS, a), "compositeRealmRoles"));
    }

    @Test
    void removeChild() {
        Uid uid = createRealmRole("parent-rm",
                AttributeBuilder.build("compositeRealmRoles", "role-a", "role-b"),
                AttributeBuilder.build("compositeClientRoles", app1Uuid + "/cr-1"));
        update(REALM_ROLE_OBJECT_CLASS, uid,
                AttributeDeltaBuilder.build("compositeRealmRoles", List.of(), List.of("role-a")),
                AttributeDeltaBuilder.build("compositeClientRoles", List.of(app1Uuid + "/cr-2"),
                        List.of(app1Uuid + "/cr-1")));
        ConnectorObject o = read(REALM_ROLE_OBJECT_CLASS, uid);
        assertEquals(Set.of("role-b"), values(o, "compositeRealmRoles"));
        assertEquals(Set.of(app1Uuid + "/cr-2"), values(o, "compositeClientRoles"));

        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("compositeRealmRoles");
        b.addValueToReplace("role-c");
        update(REALM_ROLE_OBJECT_CLASS, uid, b.build());
        assertEquals(Set.of("role-c"), values(read(REALM_ROLE_OBJECT_CLASS, uid), "compositeRealmRoles"));
    }

    @Test
    void deletingChildRoleReflectsOnRead() {
        Uid child = createRealmRole("child-del");
        Uid uid = createRealmRole("parent-del", AttributeBuilder.build("compositeRealmRoles", "child-del", "role-a"));
        connector.delete(REALM_ROLE_OBJECT_CLASS, child, null);
        assertEquals(Set.of("role-a"), values(read(REALM_ROLE_OBJECT_CLASS, uid), "compositeRealmRoles"));
    }

    @Test
    void unknownChildOnCreateLeavesNoRoleBehind() {
        assertThrows(InvalidAttributeValueException.class,
                () -> createRealmRole("half-realm", AttributeBuilder.build("compositeRealmRoles", "nope")));
        assertNull(searchByName(connector, REALM_ROLE_OBJECT_CLASS, "half-realm"));

        assertThrows(InvalidAttributeValueException.class,
                () -> createClientRole("half-client", AttributeBuilder.build("compositeClientRoles", app1Uuid + "/nope")));
        assertNull(searchByName(connector, CLIENT_ROLE_OBJECT_CLASS, app1Uuid + "/half-client"));
    }

    @Test
    void addUnknownChildOnUpdateFails() {
        Uid uid = createRealmRole("parent-unknown");
        assertThrows(InvalidAttributeValueException.class,
                () -> update(REALM_ROLE_OBJECT_CLASS, uid,
                        AttributeDeltaBuilder.build("compositeRealmRoles", List.of("nope"), List.of())));
    }

    @Test
    void realmRoleRenameCombinedWithCompositeChange() {
        Uid uid = createRealmRole("rename-realm", AttributeBuilder.build("compositeRealmRoles", "role-a"));
        update(REALM_ROLE_OBJECT_CLASS, uid,
                AttributeDeltaBuilder.build("__NAME__", "renamed-realm"),
                AttributeDeltaBuilder.build("compositeRealmRoles", List.of("role-b"), List.of("role-a")),
                AttributeDeltaBuilder.build("compositeClientRoles", List.of(app1Uuid + "/cr-1"), List.of()));
        assertNull(searchByName(connector, REALM_ROLE_OBJECT_CLASS, "rename-realm"));
        ConnectorObject o = searchByUidWithAttrs(connector, REALM_ROLE_OBJECT_CLASS, uid,
                "compositeRealmRoles", "compositeClientRoles");
        assertEquals("renamed-realm", o.getName().getNameValue());
        assertEquals(Set.of("role-b"), values(o, "compositeRealmRoles"));
        assertEquals(Set.of(app1Uuid + "/cr-1"), values(o, "compositeClientRoles"));
    }

    @Test
    void clientRoleRenameCombinedWithCompositeChange() {
        Uid uid = createClientRole("rename-client", AttributeBuilder.build("compositeRealmRoles", "role-a"));
        update(CLIENT_ROLE_OBJECT_CLASS, uid,
                AttributeDeltaBuilder.build("__NAME__", app1Uuid + "/renamed-client"),
                AttributeDeltaBuilder.build("compositeRealmRoles", List.of("role-b"), List.of("role-a")),
                AttributeDeltaBuilder.build("compositeClientRoles", List.of(app1Uuid + "/cr-2"), List.of()));
        assertNull(searchByName(connector, CLIENT_ROLE_OBJECT_CLASS, app1Uuid + "/rename-client"));
        ConnectorObject o = searchByUidWithAttrs(connector, CLIENT_ROLE_OBJECT_CLASS, uid,
                "compositeRealmRoles", "compositeClientRoles");
        assertEquals(app1Uuid + "/renamed-client", o.getName().getNameValue());
        assertEquals(Set.of("role-b"), values(o, "compositeRealmRoles"));
        assertEquals(Set.of(app1Uuid + "/cr-2"), values(o, "compositeClientRoles"));
    }

    @Test
    void clientRoleCompositesAddRemoveAndReplace() {
        Uid uid = createClientRole("parent-cc",
                AttributeBuilder.build("compositeRealmRoles", "role-a"),
                AttributeBuilder.build("compositeClientRoles", app1Uuid + "/cr-1"));

        update(CLIENT_ROLE_OBJECT_CLASS, uid,
                AttributeDeltaBuilder.build("compositeRealmRoles", List.of("role-b"), List.of("role-a")),
                AttributeDeltaBuilder.build("compositeClientRoles", List.of(app1Uuid + "/cr-2"),
                        List.of(app1Uuid + "/cr-1")));
        ConnectorObject o = read(CLIENT_ROLE_OBJECT_CLASS, uid);
        assertEquals(Set.of("role-b"), values(o, "compositeRealmRoles"));
        assertEquals(Set.of(app1Uuid + "/cr-2"), values(o, "compositeClientRoles"));

        AttributeDeltaBuilder realm = new AttributeDeltaBuilder();
        realm.setName("compositeRealmRoles");
        realm.addValueToReplace("role-c");
        AttributeDeltaBuilder client = new AttributeDeltaBuilder();
        client.setName("compositeClientRoles");
        client.addValueToReplace(app1Uuid + "/cr-1");
        update(CLIENT_ROLE_OBJECT_CLASS, uid, realm.build(), client.build());
        o = read(CLIENT_ROLE_OBJECT_CLASS, uid);
        assertEquals(Set.of("role-c"), values(o, "compositeRealmRoles"));
        assertEquals(Set.of(app1Uuid + "/cr-1"), values(o, "compositeClientRoles"));
    }
}
