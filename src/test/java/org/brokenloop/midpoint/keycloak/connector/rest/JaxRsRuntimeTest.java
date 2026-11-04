package org.brokenloop.midpoint.keycloak.connector.rest;

import jakarta.ws.rs.ext.RuntimeDelegate;
import org.brokenloop.midpoint.keycloak.connector.KeycloakConfiguration;
import org.identityconnectors.common.security.GuardedString;
import org.jboss.resteasy.core.providerfactory.ResteasyProviderFactoryImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * The REST client must not depend on whatever JAX-RS runtime delegate is already registered or discoverable.
 * <p>
 * These tests plant a foreign delegate first and then require the bundled RESTEasy one to replace it, so they fail
 * if the client stops installing its own. They do not simulate a foreign classloader (a parent loader exposing a
 * different copy of the JAX-RS API); the real proof of that is a connection test inside the host application.
 */
class JaxRsRuntimeTest {

    /** Stands in for a delegate that something else installed. */
    private static final class ForeignDelegate extends ResteasyProviderFactoryImpl {
    }

    @BeforeEach
    @AfterEach
    void forgetCachedDelegate() {
        RuntimeDelegate.setInstance(null);
    }

    private static void plantForeignDelegate() {
        RuntimeDelegate.setInstance(new ForeignDelegate());
        assertInstanceOf(ForeignDelegate.class, RuntimeDelegate.getInstance());
    }

    private static void assertBundledDelegate() {
        RuntimeDelegate delegate = RuntimeDelegate.getInstance();
        assertInstanceOf(ResteasyProviderFactoryImpl.class, delegate);
        assertFalse(delegate instanceof ForeignDelegate, "foreign delegate was not replaced");
    }

    @Test
    void installReplacesAForeignDelegate() {
        plantForeignDelegate();
        JaxRsRuntime.install();
        assertBundledDelegate();
    }

    @Test
    void creatingTheClientReplacesAForeignDelegate() {
        plantForeignDelegate();
        KeycloakConfiguration configuration = new KeycloakConfiguration();
        configuration.setServerUrl("http://localhost:1");
        configuration.setRealmName("realm");
        configuration.setClientId("client");
        configuration.setClientSecret(new GuardedString("secret".toCharArray()));

        new KeycloakAdminRESTAdminClient("test", configuration);

        assertBundledDelegate();
    }
}
