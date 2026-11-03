package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

/**
 * A confidential client with a service account in the target realm itself (not master). The server info it gets
 * has no systemInfo and no features.
 */
class KeycloakRealmScopedAccountIT extends AbstractKeycloakIT {

    static final String REALM = "it-scoped";
    static final String ORG_REALM = "it-scoped-org";

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        createServiceAccount("svc-users", "query-users", "view-users", "manage-users");
        createServiceAccount("svc-no-profile", "view-clients");
        setupRealm(ORG_REALM, true);
        createServiceAccountIn(ORG_REALM, "svc-org", "query-users", "view-users", "manage-users");
    }

    @AfterAll
    static void teardown() {
        teardownRealm(REALM);
        teardownRealm(ORG_REALM);
    }

    private static void createServiceAccount(String clientId, String... roleNames) {
        createServiceAccountIn(REALM, clientId, roleNames);
    }

    private static void createServiceAccountIn(String realmName, String clientId, String... roleNames) {
        try (Keycloak admin = adminClient()) {
            var realm = admin.realm(realmName);
            ClientRepresentation svc = new ClientRepresentation();
            svc.setClientId(clientId);
            svc.setServiceAccountsEnabled(true);
            svc.setPublicClient(false);
            svc.setStandardFlowEnabled(false);
            svc.setSecret("secret-" + clientId);
            realm.clients().create(svc).close();
            String id = realm.clients().findByClientId(clientId).get(0).getId();
            String saId = realm.clients().get(id).getServiceAccountUser().getId();
            String rmId = realm.clients().findByClientId("realm-management").get(0).getId();
            List<RoleRepresentation> roles = new java.util.ArrayList<>();
            for (String r : roleNames) {
                roles.add(realm.clients().get(rmId).roles().get(r).toRepresentation());
            }
            realm.users().get(saId).roles().clientLevel(rmId).add(roles);
        }
    }

    private static KeycloakConfiguration config(String clientId, boolean profileSchema) {
        return config(REALM, clientId, profileSchema);
    }

    private static KeycloakConfiguration config(String realmName, String clientId, boolean profileSchema) {
        KeycloakConfiguration cfg = new KeycloakConfiguration();
        cfg.setServerUrl(KEYCLOAK_URL);
        cfg.setRealmName(realmName);
        cfg.setTargetRealmName(realmName);
        cfg.setClientId(clientId);
        cfg.setClientSecret(new GuardedString(("secret-" + clientId).toCharArray()));
        cfg.setUserProfileSchemaEnabled(profileSchema);
        return cfg;
    }

    private static KeycloakConnector connector(KeycloakConfiguration cfg) {
        KeycloakConnector c = new KeycloakConnector();
        c.setInstanceName("test");
        c.init(cfg);
        return c;
    }

    @Test
    void userRolesAreEnoughToInitialiseTestAndManageUsers() {
        KeycloakConnector c = connector(config("svc-users", true));
        try {
            assertNotNull(c.schema());
            assertDoesNotThrow(c::test);

            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("alice-scoped"));
            Uid uid = c.create(USER_OBJECT_CLASS, attrs, null);
            ConnectorObject o = searchByUid(c, USER_OBJECT_CLASS, uid);
            assertNotNull(o);
            assertEquals("alice-scoped", o.getName().getNameValue());
        } finally {
            c.dispose();
        }
    }

    @Test
    void testFailsWhenTheServiceAccountCannotReadTheUserProfile() {
        KeycloakConnector c = connector(config("svc-no-profile", true));
        try {
            ConnectorException e = assertThrows(ConnectorException.class, c::test);
            assertTrue(e.getMessage().contains("user profile"), e.getMessage());
            assertTrue(e.getMessage().contains("query-users"), e.getMessage());
        } finally {
            c.dispose();
        }
        KeycloakConnector off = connector(config("svc-no-profile", false));
        try {
            assertDoesNotThrow(off::test);
        } finally {
            off.dispose();
        }
    }

    @Test
    void organizationClassIsAvailableWhenTheRealmHasOrganizations() {
        KeycloakConnector c = connector(config(ORG_REALM, "svc-org", false));
        try {
            assertNotNull(c.schema().findObjectClassInfo(KeycloakOrganizationHandler.ORGANIZATION_OBJECT_CLASS.getObjectClassValue()));
        } finally {
            c.dispose();
        }
    }
}
