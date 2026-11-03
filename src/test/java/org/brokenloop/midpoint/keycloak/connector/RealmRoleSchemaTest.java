package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import static org.brokenloop.midpoint.keycloak.connector.ConnIdTestFixtures.findAttribute;
import static org.junit.jupiter.api.Assertions.*;

class RealmRoleSchemaTest {

    @Test
    void objectClassType_isRealmRole() {
        ObjectClassInfo schema = KeycloakRealmRoleHandler.getSchema(new String[]{});
        assertEquals("realmRole", schema.getType());
    }

    @Test
    void containsUid_notCreateable() {
        ObjectClassInfo schema = KeycloakRealmRoleHandler.getSchema(new String[]{});
        AttributeInfo uid = findAttribute(schema, Uid.NAME).orElseThrow();
        assertFalse(uid.isCreateable());
        assertFalse(uid.isUpdateable());
    }

    @Test
    void containsName_required_updateable() {
        ObjectClassInfo schema = KeycloakRealmRoleHandler.getSchema(new String[]{});
        AttributeInfo name = findAttribute(schema, Name.NAME).orElseThrow();
        assertTrue(name.isRequired());
        assertTrue(name.isUpdateable());
    }

    @Test
    void containsDescription_optional() {
        ObjectClassInfo schema = KeycloakRealmRoleHandler.getSchema(new String[]{});
        AttributeInfo desc = findAttribute(schema, "description").orElseThrow();
        assertFalse(desc.isRequired());
    }

    @Test
    void containsAttributes_multiValued() {
        ObjectClassInfo schema = KeycloakRealmRoleHandler.getSchema(new String[]{});
        AttributeInfo attrs = findAttribute(schema, "attributes").orElseThrow();
        assertTrue(attrs.isMultiValued());
    }

    @Test
    void compositeAttributes_multiValued_updateable_notReturnedByDefault() {
        ObjectClassInfo schema = KeycloakRealmRoleHandler.getSchema(new String[]{});
        for (String name : new String[]{"compositeRealmRoles", "compositeClientRoles"}) {
            AttributeInfo info = findAttribute(schema, name).orElseThrow();
            assertTrue(info.isMultiValued(), name);
            assertTrue(info.isCreateable(), name);
            assertTrue(info.isUpdateable(), name);
            assertFalse(info.isReturnedByDefault(), name);
        }
    }
}
