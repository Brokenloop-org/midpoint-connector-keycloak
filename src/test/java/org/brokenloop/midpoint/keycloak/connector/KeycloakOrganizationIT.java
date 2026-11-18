package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakOrganizationHandler.*;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakOrganizationIT extends AbstractKeycloakIT {

    static final String REALM = "test-organization";
    static KeycloakConnector connector;

    @BeforeAll
    static void setup() {
        setupRealm(REALM, true);
        connector = newConnector(REALM);
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    private Set<Attribute> orgAttrs(String name) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        attrs.add(AttributeBuilder.build(ATTR_DOMAINS, name + ".example.com"));
        return attrs;
    }

    @Test
    void createOrganization_andFetchBack() {
        Uid uid = connector.create(ORGANIZATION_OBJECT_CLASS, orgAttrs("acme-corp"), null);
        assertNotNull(uid);

        ConnectorObject found = searchByUid(connector, ORGANIZATION_OBJECT_CLASS, uid);
        assertNotNull(found);
        assertEquals("acme-corp", found.getName().getNameValue());
    }

    @Test
    void updateOrganization_description() {
        // Note: KC 26 does not allow changing the alias after creation
        Uid uid = connector.create(ORGANIZATION_OBJECT_CLASS, orgAttrs("update-org"), null);

        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(ATTR_DESCRIPTION, "An updated description"));
        connector.updateDelta(ORGANIZATION_OBJECT_CLASS, uid, mods, null);

        ConnectorObject found = searchByUid(connector, ORGANIZATION_OBJECT_CLASS, uid);
        assertEquals("An updated description",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_DESCRIPTION)));
    }

    @Test
    void createOrganization_withAlias() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("aliased-org"));
        attrs.add(AttributeBuilder.build(ATTR_ALIAS, "my-alias"));
        attrs.add(AttributeBuilder.build(ATTR_DOMAINS, "aliased.example.com"));
        Uid uid = connector.create(ORGANIZATION_OBJECT_CLASS, attrs, null);

        ConnectorObject found = searchByUid(connector, ORGANIZATION_OBJECT_CLASS, uid);
        assertEquals("my-alias",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_ALIAS)));
    }

    @Test
    void deleteOrganization_succeeds() {
        Uid uid = connector.create(ORGANIZATION_OBJECT_CLASS, orgAttrs("delete-org"), null);
        connector.delete(ORGANIZATION_OBJECT_CLASS, uid, null);

        ConnectorObject found = searchByUid(connector, ORGANIZATION_OBJECT_CLASS, uid);
        assertNull(found);
    }

    @Test
    void deleteOrganization_notFound_throwsUnknownUidException() {
        assertThrows(UnknownUidException.class,
                () -> connector.delete(ORGANIZATION_OBJECT_CLASS, new Uid("non-existent-uid"), null));
    }

    @Test
    void searchAllOrganizations() {
        connector.create(ORGANIZATION_OBJECT_CLASS, orgAttrs("search-org-1"), null);
        connector.create(ORGANIZATION_OBJECT_CLASS, orgAttrs("search-org-2"), null);

        List<ConnectorObject> results = searchAll(connector, ORGANIZATION_OBJECT_CLASS);
        assertTrue(results.size() >= 2);
    }

    @Test
    void searchOrganizationByName() {
        connector.create(ORGANIZATION_OBJECT_CLASS, orgAttrs("find-by-name-org"), null);

        ConnectorObject found = searchByName(connector, ORGANIZATION_OBJECT_CLASS, "find-by-name-org");
        assertNotNull(found);
        assertEquals("find-by-name-org", found.getName().getNameValue());
    }

    @Test
    void organizationDomains_roundTrip() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("domain-org"));
        attrs.add(AttributeBuilder.build(ATTR_DOMAINS, "domain1.example.com:false", "domain2.example.com:false"));
        Uid uid = connector.create(ORGANIZATION_OBJECT_CLASS, attrs, null);

        ConnectorObject found = searchByUid(connector, ORGANIZATION_OBJECT_CLASS, uid);
        Attribute domains = found.getAttributeByName(ATTR_DOMAINS);
        assertNotNull(domains);
        assertEquals(2, domains.getValue().size());
    }

    @Test
    void organizationMembership_addAndRemove() {
        // Create a user to add as member
        Set<Attribute> userAttrs = new HashSet<>();
        userAttrs.add(new Name("org-member-user"));
        userAttrs.add(AttributeBuilder.build("email", "member@example.com"));
        userAttrs.add(AttributeBuilder.buildEnabled(true));
        Uid userUid = connector.create(USER_OBJECT_CLASS, userAttrs, null);

        // Create organization with a domain matching the user's email
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("member-org"));
        attrs.add(AttributeBuilder.build(ATTR_DOMAINS, "example.com:false"));
        Uid orgUid = connector.create(ORGANIZATION_OBJECT_CLASS, attrs, null);

        // Add user as member
        Set<AttributeDelta> addMod = new HashSet<>();
        addMod.add(AttributeDeltaBuilder.build(ATTR_MEMBERS, List.of(userUid.getUidValue()), null));
        connector.updateDelta(ORGANIZATION_OBJECT_CLASS, orgUid, addMod, null);

        // Verify membership
        ConnectorObject found = searchByUidWithAttrs(connector, ORGANIZATION_OBJECT_CLASS, orgUid, ATTR_MEMBERS);
        Attribute members = found.getAttributeByName(ATTR_MEMBERS);
        assertNotNull(members);
        assertTrue(members.getValue().contains(userUid.getUidValue()));

        // Remove member
        Set<AttributeDelta> removeMod = new HashSet<>();
        removeMod.add(AttributeDeltaBuilder.build(ATTR_MEMBERS, null, List.of(userUid.getUidValue())));
        connector.updateDelta(ORGANIZATION_OBJECT_CLASS, orgUid, removeMod, null);

        found = searchByUidWithAttrs(connector, ORGANIZATION_OBJECT_CLASS, orgUid, ATTR_MEMBERS);
        members = found.getAttributeByName(ATTR_MEMBERS);
        assertTrue(members == null || members.getValue() == null || members.getValue().isEmpty());
    }
}
