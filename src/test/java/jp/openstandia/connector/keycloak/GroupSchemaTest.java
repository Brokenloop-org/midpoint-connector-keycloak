package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import static jp.openstandia.connector.keycloak.ConnIdTestFixtures.findAttribute;
import static org.junit.jupiter.api.Assertions.*;

class GroupSchemaTest {

    @Test
    void objectClassType_isGroup() {
        ObjectClassInfo schema = KeycloakGroupHandler.getGroupSchema(new String[]{});
        assertEquals("group", schema.getType());
    }

    @Test
    void containsUid_notCreateable_notUpdateable() {
        ObjectClassInfo schema = KeycloakGroupHandler.getGroupSchema(new String[]{});
        AttributeInfo uid = findAttribute(schema, Uid.NAME).orElseThrow();
        assertFalse(uid.isCreateable());
        assertFalse(uid.isUpdateable());
    }

    @Test
    void containsName_required_updateable() {
        ObjectClassInfo schema = KeycloakGroupHandler.getGroupSchema(new String[]{});
        AttributeInfo name = findAttribute(schema, Name.NAME).orElseThrow();
        assertTrue(name.isRequired());
        assertTrue(name.isUpdateable());
    }

    @Test
    void containsPath_readOnly() {
        ObjectClassInfo schema = KeycloakGroupHandler.getGroupSchema(new String[]{});
        AttributeInfo path = findAttribute(schema, "path").orElseThrow();
        assertFalse(path.isCreateable());
        assertFalse(path.isUpdateable());
    }

    @Test
    void containsParentGroup_notReturnedByDefault() {
        ObjectClassInfo schema = KeycloakGroupHandler.getGroupSchema(new String[]{});
        AttributeInfo parentGroup = findAttribute(schema, "parentGroup").orElseThrow();
        assertFalse(parentGroup.isReturnedByDefault());
        assertFalse(parentGroup.isMultiValued());
    }

    @Test
    void customAttribute_singleValued() {
        ObjectClassInfo schema = KeycloakGroupHandler.getGroupSchema(new String[]{"description"});
        AttributeInfo desc = findAttribute(schema, "description").orElseThrow();
        assertFalse(desc.isMultiValued());
    }

    @Test
    void customAttribute_multivaluedSuffix() {
        ObjectClassInfo schema = KeycloakGroupHandler.getGroupSchema(new String[]{"tags:multivalued"});
        AttributeInfo tags = findAttribute(schema, "tags").orElseThrow();
        assertTrue(tags.isMultiValued());
    }
}
