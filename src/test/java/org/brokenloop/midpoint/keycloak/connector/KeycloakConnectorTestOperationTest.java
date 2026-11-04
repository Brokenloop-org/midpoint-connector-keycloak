package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.userprofile.config.UPConfig;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** The test() operation must surface an unreadable User Profile when the profile schema is enabled. */
class KeycloakConnectorTestOperationTest {

    private static KeycloakConnector connector(KeycloakClient stubbed, boolean profileSchema) {
        KeycloakConfiguration cfg = new KeycloakConfiguration();
        cfg.setTargetRealmName("it-test-op");
        cfg.setUserProfileSchemaEnabled(profileSchema);
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

    @Test
    void failsWhenTheUserProfileCannotBeReadAndTheSchemaIsEnabled() {
        KeycloakClient client = stub();
        when(client.getUserProfileConfig("it-test-op")).thenThrow(new RuntimeException("HTTP 403 Forbidden"));
        KeycloakConnector connector = connector(client, true);

        ConnectorException e = assertThrows(ConnectorException.class, connector::test);

        assertTrue(e.getMessage().contains("user profile"), e.getMessage());
        assertTrue(e.getMessage().contains("it-test-op"), e.getMessage());
        assertTrue(e.getMessage().contains("query-users"), e.getMessage());
        assertTrue(e.getMessage().contains("view-users"), e.getMessage());
    }

    @Test
    void passesWhenTheUserProfileCanBeRead() {
        KeycloakClient client = stub();
        when(client.getUserProfileConfig("it-test-op")).thenReturn(new UPConfig());
        assertDoesNotThrow(() -> connector(client, true).test());
    }

    @Test
    void ignoresTheUserProfileWhenTheSchemaIsDisabled() {
        KeycloakClient client = stub();
        when(client.getUserProfileConfig(any())).thenThrow(new RuntimeException("HTTP 403 Forbidden"));
        assertDoesNotThrow(() -> connector(client, false).test());
        verify(client, never()).getUserProfileConfig(any());
    }
}
