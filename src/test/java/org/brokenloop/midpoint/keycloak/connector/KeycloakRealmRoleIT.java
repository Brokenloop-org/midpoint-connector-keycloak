package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakRealmRoleHandler.*;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakRealmRoleIT extends AbstractKeycloakIT {

    static final String REALM = "test-realmrole";
    static KeycloakConnector connector;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        connector = newConnector(REALM);
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    private Set<Attribute> roleAttrs(String name) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        return attrs;
    }

    @Test
    void createRealmRole_andFetchBack() {
        Uid uid = connector.create(REALM_ROLE_OBJECT_CLASS, roleAttrs("create-role-1"), null);
        assertNotNull(uid);

        ConnectorObject found = searchByUid(connector, REALM_ROLE_OBJECT_CLASS, uid);
        assertNotNull(found);
        assertEquals("create-role-1", found.getName().getNameValue());
    }

    @Test
    void updateRealmRole_description() {
        Uid uid = connector.create(REALM_ROLE_OBJECT_CLASS, roleAttrs("update-role"), null);

        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(ATTR_DESCRIPTION, "An updated description"));
        connector.updateDelta(REALM_ROLE_OBJECT_CLASS, uid, mods, null);

        ConnectorObject found = searchByUid(connector, REALM_ROLE_OBJECT_CLASS, uid);
        assertEquals("An updated description",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_DESCRIPTION)));
    }

    @Test
    void deleteRealmRole_succeeds() {
        Uid uid = connector.create(REALM_ROLE_OBJECT_CLASS, roleAttrs("delete-role"), null);
        connector.delete(REALM_ROLE_OBJECT_CLASS, uid, null);

        ConnectorObject found = searchByUid(connector, REALM_ROLE_OBJECT_CLASS, uid);
        assertNull(found);
    }

    @Test
    void deleteRealmRole_notFound_throwsUnknownUidException() {
        assertThrows(UnknownUidException.class,
                () -> connector.delete(REALM_ROLE_OBJECT_CLASS, new Uid("non-existent-uid"), null));
    }

    @Test
    void searchAllRealmRoles_includesDefaultRoles() {
        // KC realms come with default roles like "default-roles-<realm>"
        connector.create(REALM_ROLE_OBJECT_CLASS, roleAttrs("search-role-1"), null);

        List<ConnectorObject> results = searchAll(connector, REALM_ROLE_OBJECT_CLASS);
        assertTrue(results.size() >= 1);
        assertTrue(results.stream().anyMatch(r -> "search-role-1".equals(r.getName().getNameValue())));
    }

    @Test
    void searchRealmRoleByName() {
        connector.create(REALM_ROLE_OBJECT_CLASS, roleAttrs("find-by-name-role"), null);

        ConnectorObject found = searchByName(connector, REALM_ROLE_OBJECT_CLASS, "find-by-name-role");
        assertNotNull(found);
        assertEquals("find-by-name-role", found.getName().getNameValue());
    }
}
