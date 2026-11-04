package org.brokenloop.midpoint.keycloak.connector.rest;

import jakarta.ws.rs.ext.RuntimeDelegate;
import org.brokenloop.midpoint.keycloak.connector.KeycloakConfiguration;
import org.identityconnectors.common.security.GuardedString;
import org.jboss.resteasy.core.providerfactory.ResteasyProviderFactoryImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * The REST client must not depend on the JAX-RS runtime that a host application exposes through a parent
 * classloader. Reproducing a foreign loader here is impractical, so the tests assert the outcome instead: after the
 * client is created, the installed runtime delegate is the bundled RESTEasy one.
 */
class JaxRsRuntimeTest {

    @BeforeEach
    @AfterEach
    void forgetCachedDelegate() {
        RuntimeDelegate.setInstance(null);
    }

    @Test
    void installPinsTheBundledDelegate() {
        JaxRsRuntime.install();
        assertInstanceOf(ResteasyProviderFactoryImpl.class, RuntimeDelegate.getInstance());
    }

    @Test
    void creatingTheClientPinsTheBundledDelegate() {
        KeycloakConfiguration configuration = new KeycloakConfiguration();
        configuration.setServerUrl("http://localhost:1");
        configuration.setRealmName("realm");
        configuration.setClientId("client");
        configuration.setClientSecret(new GuardedString("secret".toCharArray()));

        new KeycloakAdminRESTAdminClient("test", configuration);

        assertInstanceOf(ResteasyProviderFactoryImpl.class, RuntimeDelegate.getInstance());
    }
}
