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

import static org.brokenloop.midpoint.keycloak.connector.KeycloakGroupHandler.GROUP_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakGroupRoleMappingIT extends AbstractKeycloakIT {

    static final String REALM = "it-group-roles";
    static KeycloakConnector connector;
    static String app1Uuid;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        try (Keycloak admin = adminClient()) {
            var roles = admin.realm(REALM).roles();
            roles.create(role("role-a"));
            roles.create(role("role-b"));

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

    private Uid createGroup(String name, Attribute... extra) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        attrs.addAll(Arrays.asList(extra));
        return connector.create(GROUP_OBJECT_CLASS, attrs, null);
    }

    private Set<String> directRealm(Uid uid) {
        try (Keycloak admin = adminClient()) {
            return admin.realm(REALM).groups().group(uid.getUidValue()).roles().realmLevel().listAll()
                    .stream().map(RoleRepresentation::getName).collect(Collectors.toSet());
        }
    }

    private Set<String> directClient(Uid uid) {
        try (Keycloak admin = adminClient()) {
            return admin.realm(REALM).groups().group(uid.getUidValue()).roles().clientLevel(app1Uuid).listAll()
                    .stream().map(RoleRepresentation::getName).collect(Collectors.toSet());
        }
    }

    private Set<String> values(ConnectorObject o, String attr) {
        Attribute a = o.getAttributeByName(attr);
        if (a == null || a.getValue() == null) return Set.of();
        return a.getValue().stream().map(String::valueOf).collect(Collectors.toSet());
    }

    private void update(Uid uid, AttributeDelta... deltas) {
        connector.updateDelta(GROUP_OBJECT_CLASS, uid, new HashSet<>(Arrays.asList(deltas)), null);
    }

    @Test
    void createGroupWithRoles() {
        Uid uid = createGroup("group-create",
                AttributeBuilder.build("realmRoles", "role-a"),
                AttributeBuilder.build("clientRoles", app1Uuid + "/cr-1"));
        assertEquals(Set.of("role-a"), directRealm(uid));
        assertEquals(Set.of("cr-1"), directClient(uid));

        ConnectorObject o = searchByUidWithAttrs(connector, GROUP_OBJECT_CLASS, uid, "realmRoles", "clientRoles");
        assertEquals(Set.of("role-a"), values(o, "realmRoles"));
        assertEquals(Set.of(app1Uuid + "/cr-1"), values(o, "clientRoles"));
    }

    @Test
    void notReturnedWithoutAttributesToGet() {
        Uid uid = createGroup("group-plain", AttributeBuilder.build("realmRoles", "role-a"));
        ConnectorObject o = searchByUid(connector, GROUP_OBJECT_CLASS, uid);
        assertNull(o.getAttributeByName("realmRoles"));
        assertNull(o.getAttributeByName("clientRoles"));
    }

    @Test
    void subGroupDoesNotReportParentRoles() {
        Uid parent = createGroup("group-parent", AttributeBuilder.build("realmRoles", "role-a"));
        Uid child = createGroup("group-child", AttributeBuilder.build("parentGroup", parent.getUidValue()));
        ConnectorObject o = searchByUidWithAttrs(connector, GROUP_OBJECT_CLASS, child, "realmRoles", "clientRoles");
        assertEquals(Set.of(), values(o, "realmRoles"));
        assertEquals(Set.of(), values(o, "clientRoles"));
    }

    @Test
    void addRemoveReplace() {
        Uid uid = createGroup("group-delta", AttributeBuilder.build("realmRoles", "role-a"));
        update(uid, AttributeDeltaBuilder.build("realmRoles", List.of("role-b"), List.of("role-a")));
        assertEquals(Set.of("role-b"), directRealm(uid));

        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("realmRoles");
        b.addValueToReplace("role-a");
        update(uid, b.build());
        assertEquals(Set.of("role-a"), directRealm(uid));

        update(uid, AttributeDeltaBuilder.build("clientRoles", List.of(app1Uuid + "/cr-1"), List.of()));
        update(uid, AttributeDeltaBuilder.build("clientRoles",
                List.of(app1Uuid + "/cr-2"), List.of(app1Uuid + "/cr-1")));
        assertEquals(Set.of("cr-2"), directClient(uid));
    }

    @Test
    void addUnknownClientRoleFails() {
        Uid uid = createGroup("group-unknown");
        InvalidAttributeValueException e = assertThrows(InvalidAttributeValueException.class,
                () -> update(uid, AttributeDeltaBuilder.build("clientRoles",
                        List.of(app1Uuid + "/nope"), List.of())));
        assertTrue(e.getMessage().contains("nope"));
    }

    @Test
    void unknownRoleOnCreateLeavesNoGroupBehind() {
        assertThrows(InvalidAttributeValueException.class,
                () -> createGroup("group-halfway", AttributeBuilder.build("realmRoles", "nope")));
        assertNull(searchByName(connector, GROUP_OBJECT_CLASS, "group-halfway"));
    }

    @Test
    void unknownRoleOnUpdateLeavesGroupUnchanged() {
        Uid uid = createGroup("group-nowrite");
        assertThrows(InvalidAttributeValueException.class,
                () -> update(uid, AttributeDeltaBuilder.build("__NAME__", "group-renamed"),
                        AttributeDeltaBuilder.build("realmRoles", List.of("nope"), List.of())));
        assertNotNull(searchByName(connector, GROUP_OBJECT_CLASS, "group-nowrite"));
        assertNull(searchByName(connector, GROUP_OBJECT_CLASS, "group-renamed"));
    }
}
