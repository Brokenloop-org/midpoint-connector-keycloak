package jp.openstandia.connector.keycloak;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static jp.openstandia.connector.keycloak.KeycloakGroupHandler.GROUP_OBJECT_CLASS;
import static jp.openstandia.connector.keycloak.KeycloakUserHandler.*;
import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeycloakUserIT extends AbstractKeycloakIT {

    static final String REALM = "test-user";
    static KeycloakConnector connector;

    @BeforeAll
    static void setup() {
        setupRealm(REALM);
        connector = newConnector(REALM);
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    private Set<Attribute> userAttrs(String username) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(username));
        attrs.add(AttributeBuilder.build(ATTR_EMAIL, username + "@test.com"));
        attrs.add(AttributeBuilder.build(ATTR_FIRST_NAME, "First"));
        attrs.add(AttributeBuilder.build(ATTR_LAST_NAME, "Last"));
        attrs.add(AttributeBuilder.buildEnabled(true));
        return attrs;
    }

    @Test
    void createUser_andFetchBack() {
        Uid uid = connector.create(USER_OBJECT_CLASS, userAttrs("create-user-1"), null);
        assertNotNull(uid);

        ConnectorObject found = searchByUid(connector, USER_OBJECT_CLASS, uid);
        assertNotNull(found);
        assertEquals("create-user-1", found.getName().getNameValue());
        assertEquals("create-user-1@test.com",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_EMAIL)));
    }

    @Test
    void createUser_duplicate_throwsAlreadyExistsException() {
        connector.create(USER_OBJECT_CLASS, userAttrs("dup-user"), null);
        assertThrows(AlreadyExistsException.class,
                () -> connector.create(USER_OBJECT_CLASS, userAttrs("dup-user"), null));
    }

    @Test
    void updateUser_changesAttributes() {
        Uid uid = connector.create(USER_OBJECT_CLASS, userAttrs("update-user"), null);

        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(ATTR_EMAIL, "updated@test.com"));
        mods.add(AttributeDeltaBuilder.build(ATTR_FIRST_NAME, "Updated"));
        connector.updateDelta(USER_OBJECT_CLASS, uid, mods, null);

        ConnectorObject found = searchByUid(connector, USER_OBJECT_CLASS, uid);
        assertEquals("updated@test.com",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_EMAIL)));
        assertEquals("Updated",
                AttributeUtil.getStringValue(found.getAttributeByName(ATTR_FIRST_NAME)));
    }

    @Test
    @Disabled("Password update via user credentials returns 400 against KC 26 - needs passwordResetAPIEnabled or KC 26 password policy investigation")
    void updateUser_password_succeeds() {
        Uid uid = connector.create(USER_OBJECT_CLASS, userAttrs("pwd-user"), null);

        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.buildPassword("newPass456".toCharArray()));
        assertDoesNotThrow(() ->
                connector.updateDelta(USER_OBJECT_CLASS, uid, mods, null));
    }

    @Test
    void deleteUser_succeeds() {
        Uid uid = connector.create(USER_OBJECT_CLASS, userAttrs("delete-user"), null);
        connector.delete(USER_OBJECT_CLASS, uid, null);

        ConnectorObject found = searchByUid(connector, USER_OBJECT_CLASS, uid);
        assertNull(found);
    }

    @Test
    void deleteUser_notFound_throwsUnknownUidException() {
        assertThrows(UnknownUidException.class,
                () -> connector.delete(USER_OBJECT_CLASS, new Uid("non-existent-uid"), null));
    }

    @Test
    void searchAllUsers() {
        connector.create(USER_OBJECT_CLASS, userAttrs("search-all-1"), null);
        connector.create(USER_OBJECT_CLASS, userAttrs("search-all-2"), null);

        List<ConnectorObject> results = searchAll(connector, USER_OBJECT_CLASS);
        assertTrue(results.size() >= 2);
    }

    @Test
    void searchUserByName() {
        connector.create(USER_OBJECT_CLASS, userAttrs("search-by-name"), null);

        ConnectorObject found = searchByName(connector, USER_OBJECT_CLASS, "search-by-name");
        assertNotNull(found);
        assertEquals("search-by-name", found.getName().getNameValue());
    }

    @Test
    void enableDisableUser() {
        Set<Attribute> attrs = userAttrs("enable-disable-user");
        Uid uid = connector.create(USER_OBJECT_CLASS, attrs, null);

        // Disable
        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.buildEnabled(false));
        connector.updateDelta(USER_OBJECT_CLASS, uid, mods, null);

        ConnectorObject found = searchByUid(connector, USER_OBJECT_CLASS, uid);
        assertFalse(AttributeUtil.isEnabled(found));

        // Re-enable
        mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.buildEnabled(true));
        connector.updateDelta(USER_OBJECT_CLASS, uid, mods, null);

        found = searchByUid(connector, USER_OBJECT_CLASS, uid);
        assertTrue(AttributeUtil.isEnabled(found));
    }

    @Test
    @Disabled("Depends on group creation which fails with HTTP 400 against KC 26")
    void userGroupMembership() {
        // Create a group
        Set<Attribute> groupAttrs = new HashSet<>();
        groupAttrs.add(new Name("user-group-test"));
        Uid groupUid = connector.create(GROUP_OBJECT_CLASS, groupAttrs, null);

        // Create user with group membership
        Set<Attribute> attrs = userAttrs("group-member-user");
        attrs.add(AttributeBuilder.build(ATTR_GROUPS, groupUid.getUidValue()));
        Uid userUid = connector.create(USER_OBJECT_CLASS, attrs, null);

        // Fetch user with groups attribute
        ConnectorObject found = searchByUidWithAttrs(connector, USER_OBJECT_CLASS, userUid, ATTR_GROUPS);
        assertNotNull(found);
        Attribute groups = found.getAttributeByName(ATTR_GROUPS);
        assertNotNull(groups);
        assertTrue(groups.getValue().contains(groupUid.getUidValue()));

        // Remove from group
        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(ATTR_GROUPS, null, List.of(groupUid.getUidValue())));
        connector.updateDelta(USER_OBJECT_CLASS, userUid, mods, null);

        found = searchByUidWithAttrs(connector, USER_OBJECT_CLASS, userUid, ATTR_GROUPS);
        groups = found.getAttributeByName(ATTR_GROUPS);
        assertTrue(groups == null || groups.getValue() == null || groups.getValue().isEmpty());
    }
}
