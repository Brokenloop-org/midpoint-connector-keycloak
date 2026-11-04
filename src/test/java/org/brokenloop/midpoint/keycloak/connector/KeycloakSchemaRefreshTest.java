package org.brokenloop.midpoint.keycloak.connector;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPConfig;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** schema() rebuilds the schema and the rebuilt one is what subsequent operations use. */
class KeycloakSchemaRefreshTest {

    private static final String REALM = "it-refresh";

    private static KeycloakConnector connector(KeycloakClient stubbed) {
        KeycloakConfiguration cfg = new KeycloakConfiguration();
        cfg.setTargetRealmName(REALM);
        cfg.setUserProfileSchemaEnabled(true);
        KeycloakConnector connector = new KeycloakConnector() {
            @Override
            protected void initClient() {
                this.client = stubbed;
            }
        };
        connector.setInstanceName("test");
        connector.init(cfg);
        return connector;
    }

    private static KeycloakClient stub() {
        KeycloakClient client = mock(KeycloakClient.class);
        when(client.getVersion()).thenReturn("26.8.1");
        return client;
    }

    private static UPConfig profileWith(String... names) {
        UPConfig config = new UPConfig();
        for (String n : names) {
            config.addOrReplaceAttribute(new UPAttribute(n));
        }
        return config;
    }

    @Test
    void profileReadFailureAtInitRecoversOnSchemaRefresh() {
        KeycloakClient client = stub();
        when(client.getUserProfileConfig(REALM))
                .thenThrow(new RuntimeException("HTTP 403 Forbidden"))
                .thenReturn(profileWith("dept"));
        KeycloakConnector connector = connector(client);
        assertFalse(connector.createKeycloakHandler(USER_OBJECT_CLASS).schema.userSchema.containsKey("dept"));

        connector.schema();

        assertTrue(connector.createKeycloakHandler(USER_OBJECT_CLASS).schema.userSchema.containsKey("dept"));
    }

    @Test
    void attributeAddedAfterInitAppearsAfterRefreshOnly() {
        KeycloakClient client = stub();
        when(client.getUserProfileConfig(REALM)).thenReturn(profileWith("dept"), profileWith("dept", "team"));
        KeycloakConnector connector = connector(client);

        // operations do not re-read the profile
        connector.createKeycloakHandler(USER_OBJECT_CLASS);
        connector.createKeycloakHandler(USER_OBJECT_CLASS);
        verify(client, times(1)).getUserProfileConfig(REALM);
        assertFalse(connector.createKeycloakHandler(USER_OBJECT_CLASS).schema.userSchema.containsKey("team"));

        assertNotNull(connector.schema().findObjectClassInfo(USER_OBJECT_CLASS.getObjectClassValue())
                .getAttributeInfo().stream().filter(a -> a.is("team")).findFirst().orElse(null));
        assertTrue(connector.createKeycloakHandler(USER_OBJECT_CLASS).schema.userSchema.containsKey("team"));
    }

    @Test
    void failedRefreshKeepsThePreviousSchema() {
        KeycloakClient client = stub();
        when(client.getUserProfileConfig(REALM)).thenReturn(profileWith("dept"));
        KeycloakConnector connector = connector(client);
        when(client.getVersion()).thenThrow(new RuntimeException("boom"));

        assertThrows(RuntimeException.class, connector::schema);

        assertTrue(connector.createKeycloakHandler(USER_OBJECT_CLASS).schema.userSchema.containsKey("dept"));
    }
}
