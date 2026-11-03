package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
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
        connector.create(USER_OBJECT_CLASS, attrs, null);
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
        assertIncomplete(USER_OBJECT_CLASS, "alice", "realmRoles", "clientRoles", "federatedIdentities");
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
}
