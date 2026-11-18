package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakConfigurationTest {

    private KeycloakConfiguration config() {
        KeycloakConfiguration c = new KeycloakConfiguration();
        c.setServerUrl("http://localhost:8080");
        c.setRealmName("master");
        c.setTargetRealmName("test");
        c.setClientId("admin-cli");
        return c;
    }

    // --- validate ---

    @Test
    void validate_usernameAndPassword_succeeds() {
        KeycloakConfiguration c = config();
        c.setUsername("admin");
        c.setPassword(new GuardedString("pass".toCharArray()));
        assertDoesNotThrow(c::validate);
    }

    @Test
    void validate_usernameAndClientSecret_succeeds() {
        KeycloakConfiguration c = config();
        c.setUsername("admin");
        c.setClientSecret(new GuardedString("secret".toCharArray()));
        assertDoesNotThrow(c::validate);
    }

    @Test
    void validate_blankUsernameAndPassword_noSecret_throws() {
        KeycloakConfiguration c = config();
        // username is null, no password, no secret
        assertThrows(ConfigurationException.class, c::validate);
    }

    @Test
    void validate_clientSecretOnly_succeeds() {
        // client_credentials grant doesn't require a username; clientSecret alone
        // (with clientId set in config()) must be enough to validate.
        KeycloakConfiguration c = config();
        c.setUsername(null);
        c.setClientSecret(new GuardedString("secret".toCharArray()));

        assertDoesNotThrow(c::validate);
    }

    @Test
    void validate_usernameNoPasswordNoSecret_throws() {
        KeycloakConfiguration c = config();
        c.setUsername("admin");
        // neither password nor secret
        assertThrows(ConfigurationException.class, c::validate);
    }

    // --- getQueryPageSize ---

    @Test
    void getQueryPageSize_default_returns100() {
        KeycloakConfiguration c = config();
        assertEquals(100, c.getQueryPageSize());
    }

    @Test
    void getQueryPageSize_positiveValue_returnsThatValue() {
        KeycloakConfiguration c = config();
        c.setQueryPageSize(50);
        assertEquals(50, c.getQueryPageSize());
    }

    @Test
    void getQueryPageSize_zero_returns100() {
        KeycloakConfiguration c = config();
        c.setQueryPageSize(0);
        assertEquals(100, c.getQueryPageSize());
    }

    @Test
    void getQueryPageSize_negative_returns100() {
        KeycloakConfiguration c = config();
        c.setQueryPageSize(-5);
        assertEquals(100, c.getQueryPageSize());
    }

    // --- setGrpcPort ---

    @Test
    void setGrpcPort_setsValue() {
        KeycloakConfiguration c = config();
        c.setGrpcPort(9999);
        assertEquals(9999, c.getGrpcPort());
    }

    // --- HTTP proxy scheme ---

    @Test
    void getHttpProxyScheme_default_isHttp() {
        KeycloakConfiguration c = config();
        assertEquals("http", c.getHttpProxyScheme());
    }

    @Test
    void setHttpProxyScheme_overrides() {
        KeycloakConfiguration c = config();
        c.setHttpProxyScheme("https");
        assertEquals("https", c.getHttpProxyScheme());
    }
}
