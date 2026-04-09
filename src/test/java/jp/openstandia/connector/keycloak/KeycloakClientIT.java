package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static jp.openstandia.connector.keycloak.KeycloakClientHandler.*;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakClientIT extends AbstractKeycloakIT {

    static final String REALM = "test-client";
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

    private Set<Attribute> clientAttrs(String clientId) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(clientId));
        attrs.add(AttributeBuilder.build(ATTR_PROTOCOL, "openid-connect"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        return attrs;
    }

    @Test
    void createClient_andFetchBack() {
        Uid uid = connector.create(CLIENT_OBJECT_CLASS, clientAttrs("test-client-1"), null);
        assertNotNull(uid);

        ConnectorObject found = searchByUid(connector, CLIENT_OBJECT_CLASS, uid);
        assertNotNull(found);
        assertEquals("test-client-1", found.getName().getNameValue());
    }

    @Test
    void updateClient_nameAndDescription() {
        Uid uid = connector.create(CLIENT_OBJECT_CLASS, clientAttrs("update-client"), null);

        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(ATTR_NAME, "Updated Client Name"));
        mods.add(AttributeDeltaBuilder.build(ATTR_DESCRIPTION, "A description"));
        connector.updateDelta(CLIENT_OBJECT_CLASS, uid, mods, null);

        ConnectorObject found = searchByUid(connector, CLIENT_OBJECT_CLASS, uid);
        assertEquals("Updated Client Name",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_NAME)));
        assertEquals("A description",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_DESCRIPTION)));
    }

    @Test
    void deleteClient_succeeds() {
        Uid uid = connector.create(CLIENT_OBJECT_CLASS, clientAttrs("delete-client"), null);
        connector.delete(CLIENT_OBJECT_CLASS, uid, null);

        ConnectorObject found = searchByUid(connector, CLIENT_OBJECT_CLASS, uid);
        assertNull(found);
    }

    @Test
    void deleteClient_notFound_throwsUnknownUidException() {
        assertThrows(UnknownUidException.class,
                () -> connector.delete(CLIENT_OBJECT_CLASS, new Uid("non-existent-uid"), null));
    }

    @Test
    void searchAllClients() {
        connector.create(CLIENT_OBJECT_CLASS, clientAttrs("search-client-1"), null);
        connector.create(CLIENT_OBJECT_CLASS, clientAttrs("search-client-2"), null);

        List<ConnectorObject> results = searchAll(connector, CLIENT_OBJECT_CLASS);
        // KC creates default clients in a realm, so there should be more
        assertTrue(results.size() >= 2);
    }

    @Test
    void searchClientByName() {
        connector.create(CLIENT_OBJECT_CLASS, clientAttrs("find-client-by-name"), null);

        ConnectorObject found = searchByName(connector, CLIENT_OBJECT_CLASS, "find-client-by-name");
        assertNotNull(found);
        assertEquals("find-client-by-name", found.getName().getNameValue());
    }

    @Test
    void clientBooleanAttributes_roundTrip() {
        Set<Attribute> attrs = clientAttrs("bool-client");
        attrs.add(AttributeBuilder.build(ATTR_PUBLIC_CLIENT, true));
        attrs.add(AttributeBuilder.build(ATTR_DIRECT_ACCESS_GRANTS_ENABLED, true));
        attrs.add(AttributeBuilder.build(ATTR_SERVICE_ACCOUNT_ENABLED, false));
        Uid uid = connector.create(CLIENT_OBJECT_CLASS, attrs, null);

        ConnectorObject found = searchByUid(connector, CLIENT_OBJECT_CLASS, uid);
        assertEquals(Boolean.TRUE,
                AttributeUtil.getSingleValue(found.getAttributeByName(ATTR_PUBLIC_CLIENT)));
        assertEquals(Boolean.TRUE,
                AttributeUtil.getSingleValue(found.getAttributeByName(ATTR_DIRECT_ACCESS_GRANTS_ENABLED)));
        assertEquals(Boolean.FALSE,
                AttributeUtil.getSingleValue(found.getAttributeByName(ATTR_SERVICE_ACCOUNT_ENABLED)));
    }

    @Test
    void updateClient_redirectUris() {
        Uid uid = connector.create(CLIENT_OBJECT_CLASS, clientAttrs("redirect-client"), null);

        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(ATTR_REDIRECT_URIS,
                List.of("https://example.com/callback", "https://example.com/logout"), null));
        connector.updateDelta(CLIENT_OBJECT_CLASS, uid, mods, null);

        ConnectorObject found = searchByUid(connector, CLIENT_OBJECT_CLASS, uid);
        Attribute uris = found.getAttributeByName(ATTR_REDIRECT_URIS);
        assertNotNull(uris);
        assertEquals(2, uris.getValue().size());
        assertTrue(uris.getValue().contains("https://example.com/callback"));
    }
}
