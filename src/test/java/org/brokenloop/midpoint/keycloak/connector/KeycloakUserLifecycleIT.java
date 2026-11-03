package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakUserLifecycleIT extends AbstractKeycloakIT {

    static final String REALM = "it-lifecycle";
    static final String PASSWORD = "Passw0rd-1";
    static KeycloakConnector connector;
    static KeycloakConnector logoutConnector;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        try (Keycloak admin = adminClient()) {
            // Public client with direct grants: test fixture only, used to open a user session.
            ClientRepresentation cli = new ClientRepresentation();
            cli.setClientId("cli");
            cli.setPublicClient(true);
            cli.setDirectAccessGrantsEnabled(true);
            cli.setEnabled(true);
            admin.realm(REALM).clients().create(cli).close();
        }
        connector = newConnector(REALM);
        KeycloakConfiguration cfg = buildConfiguration(REALM);
        cfg.setLogoutOnDisable(true);
        logoutConnector = new KeycloakConnector();
        logoutConnector.setInstanceName("test-logout");
        logoutConnector.init(cfg);
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        if (logoutConnector != null) logoutConnector.dispose();
        teardownRealm(REALM);
    }

    private Uid createUser(String name, Attribute... extra) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        attrs.addAll(Arrays.asList(extra));
        return connector.create(USER_OBJECT_CLASS, attrs, null);
    }

    private Uid createUserWithPassword(String name) {
        return createUser(name,
                AttributeBuilder.build("email", name + "@example.com"),
                AttributeBuilder.build("firstName", "Test"),
                AttributeBuilder.build("lastName", "User"),
                AttributeBuilder.buildPassword(new GuardedString(PASSWORD.toCharArray())),
                AttributeBuilder.buildEnabled(true));
    }

    private static void update(KeycloakConnector c, Uid uid, AttributeDelta... deltas) {
        c.updateDelta(USER_OBJECT_CLASS, uid, new HashSet<>(Arrays.asList(deltas)), null);
    }

    private static UserRepresentation rep(Uid uid) {
        try (Keycloak admin = adminClient()) {
            return admin.realm(REALM).users().get(uid.getUidValue()).toRepresentation();
        }
    }

    private static int sessionCount(Uid uid) {
        try (Keycloak admin = adminClient()) {
            return admin.realm(REALM).users().get(uid.getUidValue()).getUserSessions().size();
        }
    }

    private static HttpResponse<String> post(String body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(
                        URI.create(KEYCLOAK_URL + "/realms/" + REALM + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
    }

    /** Opens a session via password grant and returns the refresh token. */
    private static String openSession(String username) throws Exception {
        HttpResponse<String> res = post("grant_type=password&client_id=cli&username="
                + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(PASSWORD, StandardCharsets.UTF_8));
        assertEquals(200, res.statusCode(), res.body());
        Matcher m = Pattern.compile("\"refresh_token\"\\s*:\\s*\"([^\"]+)\"").matcher(res.body());
        assertTrue(m.find(), res.body());
        return m.group(1);
    }

    private static int refresh(String refreshToken) throws Exception {
        return post("grant_type=refresh_token&client_id=cli&refresh_token=" + refreshToken).statusCode();
    }

    @Test
    void createWithRequiredActions() {
        Uid uid = createUser("alice-create",
                AttributeBuilder.build("requiredActions", "UPDATE_PASSWORD", "VERIFY_EMAIL"));
        assertEquals(Set.of("UPDATE_PASSWORD", "VERIFY_EMAIL"), new HashSet<>(rep(uid).getRequiredActions()));

        ConnectorObject o = searchByUid(connector, USER_OBJECT_CLASS, uid);
        assertEquals(Set.of("UPDATE_PASSWORD", "VERIFY_EMAIL"),
                new HashSet<>(o.getAttributeByName("requiredActions").getValue()));
    }

    @Test
    void replaceRequiredActions() {
        Uid uid = createUser("alice-replace", AttributeBuilder.build("requiredActions", "UPDATE_PASSWORD"));
        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("requiredActions");
        b.addValueToReplace("VERIFY_EMAIL", "UPDATE_PROFILE");
        update(connector, uid, b.build());
        assertEquals(Set.of("VERIFY_EMAIL", "UPDATE_PROFILE"), new HashSet<>(rep(uid).getRequiredActions()));

        update(connector, uid, AttributeDeltaBuilder.build("requiredActions",
                List.of("CONFIGURE_TOTP"), List.of("UPDATE_PROFILE")));
        assertEquals(Set.of("VERIFY_EMAIL", "CONFIGURE_TOTP"), new HashSet<>(rep(uid).getRequiredActions()));
    }

    @Test
    void disableWithLogoutEndsSessions() throws Exception {
        Uid uid = createUserWithPassword("alice-logout");
        String refreshToken = openSession("alice-logout");
        assertEquals(1, sessionCount(uid));

        update(logoutConnector, uid, AttributeDeltaBuilder.buildEnabled(false));

        assertFalse(rep(uid).isEnabled());
        assertEquals(0, sessionCount(uid));
        assertNotEquals(200, refresh(refreshToken));
    }

    @Test
    void disableWithoutFlagKeepsSessions() throws Exception {
        Uid uid = createUserWithPassword("alice-keep");
        openSession("alice-keep");

        update(connector, uid, AttributeDeltaBuilder.buildEnabled(false));

        assertFalse(rep(uid).isEnabled());
        assertEquals(1, sessionCount(uid));
    }

    @Test
    void reenableDoesNotLogout() throws Exception {
        Uid uid = createUserWithPassword("alice-reenable");
        update(logoutConnector, uid, AttributeDeltaBuilder.buildEnabled(false));
        update(logoutConnector, uid, AttributeDeltaBuilder.buildEnabled(true));
        String refreshToken = openSession("alice-reenable");

        // Updating without touching __ENABLE__, and re-enabling, must leave the session alone.
        update(logoutConnector, uid, AttributeDeltaBuilder.build("firstName", "Renamed"));
        update(logoutConnector, uid, AttributeDeltaBuilder.buildEnabled(true));

        assertEquals(1, sessionCount(uid));
        assertEquals(200, refresh(refreshToken));
    }
}
