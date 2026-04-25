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
    void validate_blankUsername_withClientSecret_throws_operatorPrecedenceBug() {
        // BUG: The validate() logic on line 328 is:
        //   if (isBlank(username) || password == null && clientSecret == null)
        // Due to operator precedence (|| binds looser than &&), this reads as:
        //   isBlank(username) || (password == null && clientSecret == null)
        // So blank username ALWAYS throws, even when clientSecret is set.
        // This prevents client_credentials-only mode (no username) from working.
        //
        // FIX: Should likely be:
        //   if ((isBlank(username) || password == null) && clientSecret == null)
        KeycloakConfiguration c = config();
        c.setUsername(null);
        c.setClientSecret(new GuardedString("secret".toCharArray()));

        // Current buggy behavior: throws even though clientSecret is set
        assertThrows(ConfigurationException.class, c::validate);
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

    // --- setGrpcPort bug ---

    @Test
    void setGrpcPort_doesNotSetValue_documentsBug() {
        // BUG: KeycloakConfiguration.setGrpcPort() on line 266-267:
        //   public void setGrpcPort(int grpcHost) {
        //       this.grpcPort = grpcPort;
        //   }
        // The parameter is named "grpcHost" (wrong), so "grpcPort" in the body
        // refers to the field itself (self-assignment). The method is a no-op.
        //
        // FIX: Rename parameter to "grpcPort" and use "this.grpcPort = grpcPort;"
        KeycloakConfiguration c = config();
        c.setGrpcPort(9999);
        // Current buggy behavior: value is NOT set, remains 0
        assertEquals(0, c.getGrpcPort());
    }
}
