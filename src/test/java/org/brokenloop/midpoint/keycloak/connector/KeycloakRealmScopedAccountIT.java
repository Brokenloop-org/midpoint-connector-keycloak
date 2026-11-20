package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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
        try (Keycloak admin = adminClient()) {
            IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
            idp.setAlias("idp-scoped");
            idp.setProviderId("saml");
            idp.setEnabled(true);
            idp.setConfig(new HashMap<>(Map.of(
                    "singleSignOnServiceUrl", "https://idp.example.com/sso",
                    "entityId", "https://idp.example.com/entity")));
            admin.realm(REALM).identityProviders().create(idp).close();
        }
        createServiceAccount("svc-users", "query-users", "view-users", "manage-users");
        createServiceAccount("svc-no-profile", "view-clients");
        createServiceAccount("svc-links", "query-users", "view-users", "manage-users", "view-identity-providers");
        setupRealm(ORG_REALM, true);
        // Before Keycloak 26.8 the realm representation a service account gets without view-realm leaves out
        // organizationsEnabled, so the connector cannot tell that organizations are on.
        if (serverOlderThan(26, 8)) {
            createServiceAccountIn(ORG_REALM, "svc-org", "query-users", "view-users", "manage-users", "view-realm");
        } else {
            createServiceAccountIn(ORG_REALM, "svc-org", "query-users", "view-users", "manage-users");
        }
    }

    private static boolean serverOlderThan(int major, int minor) {
        try (Keycloak admin = adminClient()) {
            String[] v = admin.serverInfo().getInfo().getSystemInfo().getVersion().split("\\.");
            int maj = Integer.parseInt(v[0]);
            int min = Integer.parseInt(v[1]);
            return maj < major || (maj == major && min < minor);
        }
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

    /** Linking an identity needs view-identity-providers on top of the user roles; Keycloak answers 403 without it. */
    @Test
    void identityLinksNeedViewIdentityProviders() {
        KeycloakConnector c = connector(config("svc-links", false));
        String link = "{\"identityProvider\":\"idp-scoped\",\"userId\":\"u-1\",\"userName\":\"u-1\"}";
        try {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("linked-scoped"));
            attrs.add(AttributeBuilder.build("federatedIdentities", link));
            Uid uid = c.create(USER_OBJECT_CLASS, attrs, null);

            ConnectorObject o = searchByUidWithAttrs(c, USER_OBJECT_CLASS, uid, "federatedIdentities");
            assertEquals(List.of(link), o.getAttributeByName("federatedIdentities").getValue());

            Set<Attribute> clash = new HashSet<>();
            clash.add(new Name("clash-scoped"));
            clash.add(AttributeBuilder.build("federatedIdentities", link));
            assertThrows(AlreadyExistsException.class, () -> c.create(USER_OBJECT_CLASS, clash, null));

            c.updateDelta(USER_OBJECT_CLASS, uid,
                    Set.of(AttributeDeltaBuilder.build("federatedIdentities", List.of(), List.of(link))), null);
            o = searchByUidWithAttrs(c, USER_OBJECT_CLASS, uid, "federatedIdentities");
            Attribute a = o.getAttributeByName("federatedIdentities");
            assertTrue(a == null || a.getValue() == null || a.getValue().isEmpty());
        } finally {
            c.dispose();
        }

        KeycloakConnector usersOnly = connector(config("svc-users", false));
        try {
            Set<Attribute> attrs = new HashSet<>();
            attrs.add(new Name("unlinked-scoped"));
            attrs.add(AttributeBuilder.build("federatedIdentities",
                    "{\"identityProvider\":\"idp-scoped\",\"userId\":\"u-2\",\"userName\":\"u-2\"}"));
            ConnectorException e = assertThrows(ConnectorException.class,
                    () -> usersOnly.create(USER_OBJECT_CLASS, attrs, null));
            assertTrue(e.getMessage().contains("403"), e.getMessage());
        } finally {
            usersOnly.dispose();
        }
    }
}
