package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import static org.brokenloop.midpoint.keycloak.connector.ConnIdTestFixtures.findAttribute;
import static org.junit.jupiter.api.Assertions.*;

class ClientRoleSchemaTest {

    @Test
    void objectClassType_isClientRole() {
        ObjectClassInfo schema = KeycloakClientRoleHandler.getSchema(new String[]{});
        assertEquals("clientRole", schema.getType());
    }

    @Test
    void containsUid_notCreateable() {
        ObjectClassInfo schema = KeycloakClientRoleHandler.getSchema(new String[]{});
        AttributeInfo uid = findAttribute(schema, Uid.NAME).orElseThrow();
        assertFalse(uid.isCreateable());
        assertFalse(uid.isUpdateable());
    }

    @Test
    void containsName_required_updateable() {
        ObjectClassInfo schema = KeycloakClientRoleHandler.getSchema(new String[]{});
        AttributeInfo name = findAttribute(schema, Name.NAME).orElseThrow();
        assertTrue(name.isRequired());
        assertTrue(name.isUpdateable());
    }

    @Test
    void containsDescription_optional() {
        ObjectClassInfo schema = KeycloakClientRoleHandler.getSchema(new String[]{});
        AttributeInfo desc = findAttribute(schema, "description").orElseThrow();
        assertFalse(desc.isRequired());
    }

    @Test
    void containsAttributes_multiValued() {
        ObjectClassInfo schema = KeycloakClientRoleHandler.getSchema(new String[]{});
        AttributeInfo attrs = findAttribute(schema, "attributes").orElseThrow();
        assertTrue(attrs.isMultiValued());
    }
}
