package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.*;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakGroupHandler.GROUP_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

/** With allowPartialAttributeValues the association-like attributes are returned as INCOMPLETE without values. */
class KeycloakPartialValuesIT extends AbstractKeycloakIT {

    static final String REALM = "it-partial";
    static KeycloakConnector connector;
    static String aliceUid;
    static String groupId;
    static String appUuid;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        try (Keycloak admin = adminClient()) {
            var realm = admin.realm(REALM);
            realm.roles().create(role("role-a"));
            realm.roles().create(role("role-b"));
            ClientRepresentation client = new ClientRepresentation();
            client.setClientId("app-1");
            realm.clients().create(client).close();
            String uuid = realm.clients().findByClientId("app-1").get(0).getId();
            realm.clients().get(uuid).roles().create(role("cr-1"));
            realm.roles().get("role-b").addComposites(List.of(realm.roles().get("role-a").toRepresentation()));
            GroupRepresentation group = new GroupRepresentation();
            group.setName("group-1");
            realm.groups().add(group).close();

            IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
            idp.setAlias("idp-1");
            idp.setProviderId("saml");
            idp.setEnabled(true);
            idp.setConfig(new HashMap<>(Map.of(
                    "singleSignOnServiceUrl", "https://idp.example.com/sso",
                    "entityId", "https://idp.example.com/entity")));
            realm.identityProviders().create(idp).close();
        }
        connector = newConnector(REALM);
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("alice"));
        aliceUid = connector.create(USER_OBJECT_CLASS, attrs, null).getUidValue();
        Set<Attribute> bob = new HashSet<>();
        bob.add(new Name("bob"));
        connector.create(USER_OBJECT_CLASS, bob, null);

        try (Keycloak admin = adminClient()) {
            var realm = admin.realm(REALM);
            var alice = realm.users().get(aliceUid);
            alice.roles().realmLevel().add(List.of(realm.roles().get("role-a").toRepresentation()));
            appUuid = realm.clients().findByClientId("app-1").get(0).getId();
            alice.roles().clientLevel(appUuid).add(
                    List.of(realm.clients().get(appUuid).roles().get("cr-1").toRepresentation()));
            groupId = realm.groups().groups("group-1", 0, 1).get(0).getId();
            alice.joinGroup(groupId);
            FederatedIdentityRepresentation link = new FederatedIdentityRepresentation();
            link.setIdentityProvider("idp-1");
            link.setUserId("ext-alice");
            link.setUserName("alice-ext");
            alice.addFederatedIdentity("idp-1", link).close();
        }
    }

    private static KeycloakConnector connectorCompleting(String... attrs) {
        KeycloakConfiguration cfg = buildConfiguration(REALM);
        cfg.setCompleteAttributesOnSearch(attrs);
        KeycloakConnector c = new KeycloakConnector();
        c.setInstanceName("test");
        c.init(cfg);
        return c;
    }

    private static ConnectorObject findUser(KeycloakConnector c, String name, OperationOptions options) {
        List<ConnectorObject> results = new ArrayList<>();
        c.executeQuery(USER_OBJECT_CLASS, null, results::add, options);
        return results.stream().filter(r -> name.equals(r.getName().getNameValue())).findFirst()
                .orElseThrow(() -> new AssertionError("no user " + name));
    }

    private static void assertComplete(ConnectorObject o, String attrName, Object... expected) {
        Attribute a = o.getAttributeByName(attrName);
        assertNotNull(a, attrName + " missing");
        assertEquals(AttributeValueCompleteness.COMPLETE, a.getAttributeValueCompleteness(), attrName);
        assertEquals(new HashSet<>(Arrays.asList(expected)), new HashSet<>(a.getValue()), attrName);
    }

    private static void assertIncompleteAttr(ConnectorObject o, String attrName) {
        Attribute a = o.getAttributeByName(attrName);
        assertNotNull(a, attrName + " missing");
        assertEquals(AttributeValueCompleteness.INCOMPLETE, a.getAttributeValueCompleteness(), attrName);
        assertTrue(a.getValue() == null || a.getValue().isEmpty(), attrName + " must carry no values");
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    private static RoleRepresentation role(String name) {
        RoleRepresentation r = new RoleRepresentation();
        r.setName(name);
        return r;
    }

    private static void assertIncomplete(ObjectClass oc, String name, String... attrNames) {
        List<ConnectorObject> results = new ArrayList<>();
        connector.executeQuery(oc, null, results::add, ConnIdTestFixtures.optionsWithPartialValues());
        ConnectorObject o = results.stream().filter(r -> name.equals(r.getName().getNameValue()) || r.getName().getNameValue().endsWith("/" + name)).findFirst().orElse(null);
        assertNotNull(o, "no " + oc.getObjectClassValue() + " named " + name);
        for (String attrName : attrNames) {
            Attribute a = o.getAttributeByName(attrName);
            assertNotNull(a, attrName + " missing");
            assertEquals(AttributeValueCompleteness.INCOMPLETE, a.getAttributeValueCompleteness(), attrName);
            assertTrue(a.getValue() == null || a.getValue().isEmpty(), attrName + " must carry no values");
        }
    }

    @Test
    void userAssociationsAreIncomplete() {
        assertIncomplete(USER_OBJECT_CLASS, "alice", "groups", "realmRoles", "clientRoles", "federatedIdentities");
    }

    @Test
    void groupRoleMappingsAreIncomplete() {
        assertIncomplete(GROUP_OBJECT_CLASS, "group-1", "realmRoles", "clientRoles");
    }

    @Test
    void realmRoleCompositesAreIncomplete() {
        assertIncomplete(REALM_ROLE_OBJECT_CLASS, "role-b", "compositeRealmRoles", "compositeClientRoles");
    }

    @Test
    void clientRoleCompositesAreIncomplete() {
        assertIncomplete(CLIENT_ROLE_OBJECT_CLASS, "cr-1", "compositeRealmRoles", "compositeClientRoles");
    }

    @Test
    void listedRealmRolesAreCompleteOnPartialSearch() {
        KeycloakConnector c = connectorCompleting("realmRoles");
        try {
            ConnectorObject alice = findUser(c, "alice", ConnIdTestFixtures.optionsWithPartialValues());
            assertComplete(alice, "realmRoles", "role-a");
            assertIncompleteAttr(alice, "clientRoles");
            assertIncompleteAttr(alice, "groups");
            assertIncompleteAttr(alice, "federatedIdentities");
        } finally {
            c.dispose();
        }
    }

    @Test
    void eachCompletableAttributeIsCompleteWhenListed() {
        KeycloakConnector c = connectorCompleting("groups", "realmRoles", "clientRoles", "federatedIdentities");
        try {
            ConnectorObject alice = findUser(c, "alice", ConnIdTestFixtures.optionsWithPartialValues());
            FederatedIdentityRepresentation link = new FederatedIdentityRepresentation();
            link.setIdentityProvider("idp-1");
            link.setUserId("ext-alice");
            link.setUserName("alice-ext");
            assertComplete(alice, "groups", groupId);
            assertComplete(alice, "realmRoles", "role-a");
            assertComplete(alice, "clientRoles", appUuid + "/cr-1");
            assertComplete(alice, "federatedIdentities", FederatedIdentityCodec.format(link));
        } finally {
            c.dispose();
        }
    }

    @Test
    void listedAttributeIsCompleteOnPartialGetByUid() {
        KeycloakConnector c = connectorCompleting("realmRoles");
        try {
            List<ConnectorObject> results = new ArrayList<>();
            c.executeQuery(USER_OBJECT_CLASS, KeycloakFilter.By(new Uid(aliceUid)), results::add,
                    ConnIdTestFixtures.optionsWithPartialValues());
            assertEquals(1, results.size());
            assertComplete(results.get(0), "realmRoles", "role-a");
        } finally {
            c.dispose();
        }
    }

    @Test
    void listedAttributeLeftOutOfAttributesToGetStaysIncomplete() {
        KeycloakConnector c = connectorCompleting("realmRoles");
        try {
            OperationOptions options = new OperationOptionsBuilder()
                    .setAllowPartialAttributeValues(true)
                    .setAttributesToGet("email")
                    .build();
            ConnectorObject alice = findUser(c, "alice", options);
            assertIncompleteAttr(alice, "realmRoles");
        } finally {
            c.dispose();
        }
    }

    @Test
    void listedAttributeOnUserWithoutMappingsIsEmptyAndComplete() {
        KeycloakConnector c = connectorCompleting("realmRoles", "federatedIdentities");
        try {
            ConnectorObject bob = findUser(c, "bob", ConnIdTestFixtures.optionsWithPartialValues());
            assertComplete(bob, "realmRoles");
            assertComplete(bob, "federatedIdentities");
        } finally {
            c.dispose();
        }
    }

    @Test
    void listedAttributeIsCompleteWhenDefaultAttributesAreRequested() {
        KeycloakConnector c = connectorCompleting("realmRoles");
        try {
            OperationOptions options = new OperationOptionsBuilder()
                    .setAllowPartialAttributeValues(true)
                    .setReturnDefaultAttributes(true)
                    .build();
            ConnectorObject alice = findUser(c, "alice", options);
            assertComplete(alice, "realmRoles", "role-a");
            assertIncompleteAttr(alice, "groups");
        } finally {
            c.dispose();
        }
    }

    @Test
    void listedAttributeIsCompleteWhenDefaultAttributesPlusOthersAreRequested() {
        KeycloakConnector c = connectorCompleting("realmRoles");
        try {
            OperationOptions options = new OperationOptionsBuilder()
                    .setAllowPartialAttributeValues(true)
                    .setReturnDefaultAttributes(true)
                    .setAttributesToGet("clientRoles")
                    .build();
            ConnectorObject alice = findUser(c, "alice", options);
            assertComplete(alice, "realmRoles", "role-a");
        } finally {
            c.dispose();
        }
    }

    @Test
    void listedAttributeIsCompleteOnPartialGetByName() {
        KeycloakConnector c = connectorCompleting("realmRoles");
        try {
            List<ConnectorObject> results = new ArrayList<>();
            c.executeQuery(USER_OBJECT_CLASS, KeycloakFilter.By(new Name("alice")), results::add,
                    ConnIdTestFixtures.optionsWithPartialValues());
            assertEquals(1, results.size());
            assertComplete(results.get(0), "realmRoles", "role-a");
        } finally {
            c.dispose();
        }
    }
}
