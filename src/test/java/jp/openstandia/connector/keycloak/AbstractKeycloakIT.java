package jp.openstandia.connector.keycloak;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.BeforeAll;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.RealmRepresentation;

import java.net.HttpURLConnection;
import java.net.URI;
import java.util.*;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Base class for integration tests against a live Keycloak instance.
 *
 * Expects Keycloak running at the URL defined by the system property
 * {@code keycloak.url} (default: {@code http://localhost:8090}).
 *
 * Start Keycloak via: {@code docker compose up -d}
 * Run tests via:      {@code mvn verify -Dgpg.skip=true}
 */
abstract class AbstractKeycloakIT {

    static final String KEYCLOAK_URL = System.getProperty("keycloak.url", "http://localhost:8090");
    static final String ADMIN_USER = System.getProperty("keycloak.admin.user", "admin");
    static final String ADMIN_PASS = System.getProperty("keycloak.admin.pass", "admin");

    @BeforeAll
    static void ensureKeycloakAvailable() {
        assumeTrue(isKeycloakReachable(),
                "Keycloak not reachable at " + KEYCLOAK_URL + ". Start it with: docker compose up -d");
    }

    protected static String setupRealm(String realmName) {
        return setupRealm(realmName, false);
    }

    protected static String setupRealm(String realmName, boolean organizationsEnabled) {
        try (Keycloak admin = adminClient()) {
            try {
                admin.realm(realmName).remove();
            } catch (Exception ignored) {
            }
            RealmRepresentation realm = new RealmRepresentation();
            realm.setRealm(realmName);
            realm.setEnabled(true);
            if (organizationsEnabled) {
                realm.setOrganizationsEnabled(true);
            }
            admin.realms().create(realm);
        }
        return realmName;
    }

    protected static void teardownRealm(String realmName) {
        if (realmName == null) return;
        try (Keycloak admin = adminClient()) {
            admin.realm(realmName).remove();
        } catch (Exception ignored) {
        }
    }

    static Keycloak adminClient() {
        return KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK_URL)
                .realm("master")
                .grantType("password")
                .clientId("admin-cli")
                .username(ADMIN_USER)
                .password(ADMIN_PASS)
                .build();
    }

    static KeycloakConfiguration buildConfiguration(String realmName) {
        KeycloakConfiguration config = new KeycloakConfiguration();
        config.setServerUrl(KEYCLOAK_URL);
        config.setRealmName("master");
        config.setTargetRealmName(realmName);
        config.setClientId("admin-cli");
        config.setUsername(ADMIN_USER);
        config.setPassword(new GuardedString(ADMIN_PASS.toCharArray()));
        return config;
    }

    static KeycloakConnector newConnector(String realmName) {
        KeycloakConnector connector = new KeycloakConnector();
        connector.setInstanceName("test");
        connector.init(buildConfiguration(realmName));
        return connector;
    }

    static KeycloakConnector newConnectorWithPageSize(String realmName, int pageSize) {
        KeycloakConfiguration cfg = buildConfiguration(realmName);
        cfg.setQueryPageSize(pageSize);
        KeycloakConnector connector = new KeycloakConnector();
        connector.setInstanceName("test");
        connector.init(cfg);
        return connector;
    }

    // --- Search helpers ---

    static List<ConnectorObject> searchAll(KeycloakConnector connector, ObjectClass objectClass) {
        List<ConnectorObject> results = new ArrayList<>();
        connector.executeQuery(objectClass, null, results::add, new OperationOptionsBuilder().build());
        return results;
    }

    static ConnectorObject searchByUid(KeycloakConnector connector, ObjectClass objectClass, Uid uid) {
        List<ConnectorObject> results = new ArrayList<>();
        KeycloakFilter filter = KeycloakFilter.By(uid);
        connector.executeQuery(objectClass, filter, results::add, new OperationOptionsBuilder().build());
        return results.isEmpty() ? null : results.get(0);
    }

    static ConnectorObject searchByName(KeycloakConnector connector, ObjectClass objectClass, String name) {
        List<ConnectorObject> results = new ArrayList<>();
        KeycloakFilter filter = KeycloakFilter.By(new Name(name));
        connector.executeQuery(objectClass, filter, results::add, new OperationOptionsBuilder().build());
        return results.isEmpty() ? null : results.get(0);
    }

    static ConnectorObject searchByUidWithAttrs(KeycloakConnector connector, ObjectClass objectClass,
                                                 Uid uid, String... attrs) {
        List<ConnectorObject> results = new ArrayList<>();
        KeycloakFilter filter = KeycloakFilter.By(uid);
        OperationOptions opts = new OperationOptionsBuilder()
                .setAttributesToGet(attrs)
                .build();
        connector.executeQuery(objectClass, filter, results::add, opts);
        return results.isEmpty() ? null : results.get(0);
    }

    private static boolean isKeycloakReachable() {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(KEYCLOAK_URL + "/realms/master").toURL().openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.setRequestMethod("GET");
            int code = conn.getResponseCode();
            conn.disconnect();
            return code == 200;
        } catch (Exception e) {
            return false;
        }
    }
}
