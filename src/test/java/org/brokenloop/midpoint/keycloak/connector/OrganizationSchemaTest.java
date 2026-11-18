package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import static org.brokenloop.midpoint.keycloak.connector.ConnIdTestFixtures.findAttribute;
import static org.junit.jupiter.api.Assertions.*;

class OrganizationSchemaTest {

    @Test
    void objectClassType_isOrganization() {
        ObjectClassInfo schema = KeycloakOrganizationHandler.getSchema(new String[]{});
        assertEquals("organization", schema.getType());
    }

    @Test
    void containsUid_notCreateable() {
        ObjectClassInfo schema = KeycloakOrganizationHandler.getSchema(new String[]{});
        AttributeInfo uid = findAttribute(schema, Uid.NAME).orElseThrow();
        assertFalse(uid.isCreateable());
        assertFalse(uid.isUpdateable());
    }

    @Test
    void containsName_required_updateable() {
        ObjectClassInfo schema = KeycloakOrganizationHandler.getSchema(new String[]{});
        AttributeInfo name = findAttribute(schema, Name.NAME).orElseThrow();
        assertTrue(name.isRequired());
        assertTrue(name.isUpdateable());
    }

    @Test
    void containsEnable() {
        ObjectClassInfo schema = KeycloakOrganizationHandler.getSchema(new String[]{});
        assertTrue(findAttribute(schema, OperationalAttributes.ENABLE_NAME).isPresent());
    }

    @Test
    void containsAlias_optional() {
        ObjectClassInfo schema = KeycloakOrganizationHandler.getSchema(new String[]{});
        AttributeInfo alias = findAttribute(schema, "alias").orElseThrow();
        assertFalse(alias.isRequired());
    }

    @Test
    void containsDomains_multiValued() {
        ObjectClassInfo schema = KeycloakOrganizationHandler.getSchema(new String[]{});
        AttributeInfo domains = findAttribute(schema, "domains").orElseThrow();
        assertTrue(domains.isMultiValued());
    }

    @Test
    void containsMembers_multiValued_notReturnedByDefault() {
        ObjectClassInfo schema = KeycloakOrganizationHandler.getSchema(new String[]{});
        AttributeInfo members = findAttribute(schema, "members").orElseThrow();
        assertTrue(members.isMultiValued());
        assertFalse(members.isReturnedByDefault());
    }

    @Test
    void containsAttributes_multiValued() {
        ObjectClassInfo schema = KeycloakOrganizationHandler.getSchema(new String[]{});
        AttributeInfo attrs = findAttribute(schema, "attributes").orElseThrow();
        assertTrue(attrs.isMultiValued());
    }
}
