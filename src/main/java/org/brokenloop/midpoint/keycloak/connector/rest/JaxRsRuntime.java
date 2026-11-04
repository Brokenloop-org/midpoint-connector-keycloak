package org.brokenloop.midpoint.keycloak.connector.rest;

import jakarta.ws.rs.ext.RuntimeDelegate;
import org.jboss.resteasy.core.providerfactory.ResteasyProviderFactoryImpl;

/**
 * Pins the JAX-RS runtime to the implementation bundled with the connector.
 * <p>
 * {@link RuntimeDelegate#getInstance()} looks its implementation up with {@link java.util.ServiceLoader}, which also
 * sees the JAX-RS implementation of the host application through the parent classloader. That one implements the
 * host's copy of the API, not the bundled one, so the lookup fails with a {@code ServiceConfigurationError}
 * ("not a subtype"). Installing the bundled delegate up front makes the lookup independent of the host.
 */
final class JaxRsRuntime {

    private JaxRsRuntime() {
    }

    /** Installs the bundled delegate, replacing whatever the lookup would have found. Safe to call repeatedly. */
    static void install() {
        RuntimeDelegate.setInstance(new ResteasyProviderFactoryImpl());
    }
}
