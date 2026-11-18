package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.Schema;
import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakConnectorIT extends AbstractKeycloakIT {

    static final String REALM = "test-connector";
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

    @Test
    void test_connectionSucceeds() {
        assertDoesNotThrow(() -> connector.test());
    }

    @Test
    void serverVersionMatchesExpected() {
        String expected = System.getProperty("keycloak.expectedVersion");
        Assumptions.assumeTrue(expected != null && !expected.isBlank(), "keycloak.expectedVersion not set");
        assertTrue(connector.client.getVersion().startsWith(expected),
                "Expected Keycloak " + expected + " but was " + connector.client.getVersion());
    }

    @Test
    void schema_containsAllObjectClasses() {
        Schema schema = connector.schema();
        assertNotNull(schema);

        ObjectClassInfo userInfo = schema.findObjectClassInfo("user");
        assertNotNull(userInfo, "Schema should contain 'user' object class");

        ObjectClassInfo groupInfo = schema.findObjectClassInfo("group");
        assertNotNull(groupInfo, "Schema should contain 'group' object class");

        ObjectClassInfo clientInfo = schema.findObjectClassInfo("client");
        assertNotNull(clientInfo, "Schema should contain 'client' object class");

        ObjectClassInfo clientRoleInfo = schema.findObjectClassInfo("clientRole");
        assertNotNull(clientRoleInfo, "Schema should contain 'clientRole' object class");
    }

    @Test
    void schema_userHasExpectedAttributes() {
        Schema schema = connector.schema();
        ObjectClassInfo userInfo = schema.findObjectClassInfo("user");

        assertTrue(userInfo.getAttributeInfo().stream()
                .anyMatch(a -> a.getName().equals("email")));
        assertTrue(userInfo.getAttributeInfo().stream()
                .anyMatch(a -> a.getName().equals("firstName")));
        assertTrue(userInfo.getAttributeInfo().stream()
                .anyMatch(a -> a.getName().equals("groups")));
    }
}
