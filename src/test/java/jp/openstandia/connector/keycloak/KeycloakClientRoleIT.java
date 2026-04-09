package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static jp.openstandia.connector.keycloak.KeycloakClientHandler.CLIENT_OBJECT_CLASS;
import static jp.openstandia.connector.keycloak.KeycloakClientRoleHandler.*;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakClientRoleIT extends AbstractKeycloakIT {

    static final String REALM = "test-clientrole";
    static KeycloakConnector connector;
    static Uid clientUid;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        connector = newConnector(REALM);

        // Create a client to hold roles
        Set<Attribute> clientAttrs = new HashSet<>();
        clientAttrs.add(new Name("role-test-client"));
        clientAttrs.add(AttributeBuilder.build("protocol", "openid-connect"));
        clientAttrs.add(AttributeBuilder.buildEnabled(true));
        clientUid = connector.create(CLIENT_OBJECT_CLASS, clientAttrs, null);
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    private Set<Attribute> roleAttrs(String roleName) {
        // Client role name format: <clientUUID>/<roleName>
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(clientUid.getUidValue() + "/" + roleName));
        return attrs;
    }

    @Test
    void createClientRole_andFetchBack() {
        Uid uid = connector.create(CLIENT_ROLE_OBJECT_CLASS, roleAttrs("test-role"), null);
        assertNotNull(uid);

        ConnectorObject found = searchByUid(connector, CLIENT_ROLE_OBJECT_CLASS, uid);
        assertNotNull(found);
        assertTrue(found.getName().getNameValue().endsWith("test-role"));
    }

    @Test
    void updateClientRole_description() {
        Uid uid = connector.create(CLIENT_ROLE_OBJECT_CLASS, roleAttrs("update-role"), null);

        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(ATTR_DESCRIPTION, "Updated description"));
        connector.updateDelta(CLIENT_ROLE_OBJECT_CLASS, uid, mods, null);

        ConnectorObject found = searchByUid(connector, CLIENT_ROLE_OBJECT_CLASS, uid);
        assertEquals("Updated description",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_DESCRIPTION)));
    }

    @Test
    void deleteClientRole_succeeds() {
        Uid uid = connector.create(CLIENT_ROLE_OBJECT_CLASS, roleAttrs("delete-role"), null);
        connector.delete(CLIENT_ROLE_OBJECT_CLASS, uid, null);

        ConnectorObject found = searchByUid(connector, CLIENT_ROLE_OBJECT_CLASS, uid);
        assertNull(found);
    }

    @Test
    void searchAllClientRoles() {
        connector.create(CLIENT_ROLE_OBJECT_CLASS, roleAttrs("search-role-1"), null);
        connector.create(CLIENT_ROLE_OBJECT_CLASS, roleAttrs("search-role-2"), null);

        List<ConnectorObject> results = searchAll(connector, CLIENT_ROLE_OBJECT_CLASS);
        assertTrue(results.size() >= 2);
    }
}
