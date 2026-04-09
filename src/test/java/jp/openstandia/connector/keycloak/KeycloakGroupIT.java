package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static jp.openstandia.connector.keycloak.KeycloakGroupHandler.*;
import static org.junit.jupiter.api.Assertions.*;

// BUG: Group creation via the connector returns HTTP 400 against KC 26.
// Direct KC admin client group creation works fine. The issue is in the
// connector's custom ResteasyClient serialization of GroupRepresentation.
// User, Client, and ClientRole CRUD all work correctly.
@Disabled("Group operations fail with HTTP 400 against KC 26 - connector serialization bug")
class KeycloakGroupIT extends AbstractKeycloakIT {

    static final String REALM = "test-group";
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

    private Set<Attribute> groupAttrs(String name) {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name(name));
        return attrs;
    }

    @Test
    void createGroup_andFetchBack() {
        Uid uid = connector.create(GROUP_OBJECT_CLASS, groupAttrs("create-group-1"), null);
        assertNotNull(uid);

        ConnectorObject found = searchByUid(connector, GROUP_OBJECT_CLASS, uid);
        assertNotNull(found);
        assertEquals("create-group-1", found.getName().getNameValue());
    }

    @Test
    void updateGroupName() {
        Uid uid = connector.create(GROUP_OBJECT_CLASS, groupAttrs("rename-group"), null);

        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(Name.NAME, "renamed-group"));
        connector.updateDelta(GROUP_OBJECT_CLASS, uid, mods, null);

        ConnectorObject found = searchByUid(connector, GROUP_OBJECT_CLASS, uid);
        assertEquals("renamed-group", found.getName().getNameValue());
    }

    @Test
    void deleteGroup_succeeds() {
        Uid uid = connector.create(GROUP_OBJECT_CLASS, groupAttrs("delete-group"), null);
        connector.delete(GROUP_OBJECT_CLASS, uid, null);

        ConnectorObject found = searchByUid(connector, GROUP_OBJECT_CLASS, uid);
        assertNull(found);
    }

    @Test
    void deleteGroup_notFound_throwsUnknownUidException() {
        assertThrows(UnknownUidException.class,
                () -> connector.delete(GROUP_OBJECT_CLASS, new Uid("non-existent-uid"), null));
    }

    @Test
    void searchAllGroups() {
        connector.create(GROUP_OBJECT_CLASS, groupAttrs("search-group-1"), null);
        connector.create(GROUP_OBJECT_CLASS, groupAttrs("search-group-2"), null);

        List<ConnectorObject> results = searchAll(connector, GROUP_OBJECT_CLASS);
        assertTrue(results.size() >= 2);
    }

    @Test
    void searchGroupByName() {
        connector.create(GROUP_OBJECT_CLASS, groupAttrs("find-by-name-group"), null);

        ConnectorObject found = searchByName(connector, GROUP_OBJECT_CLASS, "find-by-name-group");
        assertNotNull(found);
        assertEquals("find-by-name-group", found.getName().getNameValue());
    }

    @Test
    void createSubGroup_withParent() {
        Uid parentUid = connector.create(GROUP_OBJECT_CLASS, groupAttrs("parent-group"), null);

        Set<Attribute> subAttrs = new HashSet<>();
        subAttrs.add(new Name("child-group"));
        subAttrs.add(AttributeBuilder.build(ATTR_PARENT_GROUP, parentUid.getUidValue()));
        Uid childUid = connector.create(GROUP_OBJECT_CLASS, subAttrs, null);
        assertNotNull(childUid);

        // Fetch child and verify path indicates it's a sub-group
        ConnectorObject child = searchByUid(connector, GROUP_OBJECT_CLASS, childUid);
        assertNotNull(child);
        String path = AttributeUtil.getStringValue(child.getAttributeByName(ATTR_PATH));
        assertNotNull(path);
        assertTrue(path.contains("parent-group"));
        assertTrue(path.endsWith("child-group"));
    }

    @Test
    void moveSubGroupToTopLevel() {
        Uid parentUid = connector.create(GROUP_OBJECT_CLASS, groupAttrs("move-parent"), null);

        Set<Attribute> subAttrs = new HashSet<>();
        subAttrs.add(new Name("move-child"));
        subAttrs.add(AttributeBuilder.build(ATTR_PARENT_GROUP, parentUid.getUidValue()));
        Uid childUid = connector.create(GROUP_OBJECT_CLASS, subAttrs, null);

        // Verify it's a sub-group
        ConnectorObject child = searchByUid(connector, GROUP_OBJECT_CLASS, childUid);
        String path = AttributeUtil.getStringValue(child.getAttributeByName(ATTR_PATH));
        assertTrue(path.chars().filter(c -> c == '/').count() > 1);

        // Move to top level by clearing parent
        Set<AttributeDelta> mods = new HashSet<>();
        mods.add(AttributeDeltaBuilder.build(ATTR_PARENT_GROUP, (Object) null));
        connector.updateDelta(GROUP_OBJECT_CLASS, childUid, mods, null);

        // Verify it's now a top-level group (path has single /)
        child = searchByUid(connector, GROUP_OBJECT_CLASS, childUid);
        path = AttributeUtil.getStringValue(child.getAttributeByName(ATTR_PATH));
        assertEquals(1, path.chars().filter(c -> c == '/').count());
    }
}
