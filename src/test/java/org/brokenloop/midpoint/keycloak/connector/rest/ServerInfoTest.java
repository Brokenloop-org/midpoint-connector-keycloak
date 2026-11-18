package org.brokenloop.midpoint.keycloak.connector.rest;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.info.FeatureRepresentation;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.keycloak.representations.info.SystemInfoRepresentation;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** A service account of the target realm gets a server info without systemInfo and features. */
class ServerInfoTest {

    @Test
    void versionIsUnknownWithoutSystemInfo() {
        assertEquals("unknown", KeycloakAdminRESTAdminClient.versionOf(new ServerInfoRepresentation()));
        assertEquals("unknown", KeycloakAdminRESTAdminClient.versionOf(null));
    }

    @Test
    void versionIsReadFromSystemInfo() {
        ServerInfoRepresentation info = new ServerInfoRepresentation();
        SystemInfoRepresentation sys = new SystemInfoRepresentation();
        sys.setVersion("26.8.1");
        info.setSystemInfo(sys);
        assertEquals("26.8.1", KeycloakAdminRESTAdminClient.versionOf(info));
    }

    @Test
    void absentFeaturesDoNotClaimTheFeatureIsOff() {
        assertTrue(KeycloakAdminRESTAdminClient.featureEnabled(new ServerInfoRepresentation(), "organization"));
    }

    @Test
    void presentFeaturesDecide() {
        ServerInfoRepresentation info = new ServerInfoRepresentation();
        FeatureRepresentation off = new FeatureRepresentation();
        off.setName("ORGANIZATION");
        off.setEnabled(false);
        info.setFeatures(List.of(off));
        assertFalse(KeycloakAdminRESTAdminClient.featureEnabled(info, "organization"));
        off.setEnabled(true);
        assertTrue(KeycloakAdminRESTAdminClient.featureEnabled(info, "organization"));
    }
}
