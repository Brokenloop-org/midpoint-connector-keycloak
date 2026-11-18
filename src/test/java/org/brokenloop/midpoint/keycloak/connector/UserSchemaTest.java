package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.Optional;

import static org.brokenloop.midpoint.keycloak.connector.ConnIdTestFixtures.findAttribute;
import static org.junit.jupiter.api.Assertions.*;

class UserSchemaTest {

    @Test
    void objectClassType_isUser() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        assertEquals("user", schema.getType());
    }

    @Test
    void containsUid_notCreateable_notUpdateable() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        AttributeInfo uid = findAttribute(schema, Uid.NAME).orElseThrow();
        assertFalse(uid.isRequired());
        assertFalse(uid.isCreateable());
        assertFalse(uid.isUpdateable());
    }

    @Test
    void containsName_required_updateable() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        AttributeInfo name = findAttribute(schema, Name.NAME).orElseThrow();
        assertTrue(name.isRequired());
        assertTrue(name.isUpdateable());
    }

    @Test
    void containsEmail_optional_updateable() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        AttributeInfo email = findAttribute(schema, "email").orElseThrow();
        assertFalse(email.isRequired());
        assertTrue(email.isUpdateable());
    }

    @Test
    void containsEmailVerified_booleanType() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        AttributeInfo emailVerified = findAttribute(schema, "emailVerified").orElseThrow();
        assertEquals(Boolean.class, emailVerified.getType());
    }

    @Test
    void containsEnable() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        assertTrue(findAttribute(schema, OperationalAttributes.ENABLE_NAME).isPresent());
    }

    @Test
    void containsPassword() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        assertTrue(findAttribute(schema, OperationalAttributes.PASSWORD_NAME).isPresent());
    }

    @Test
    void containsCreatedTimestamp_readOnly_zonedDateTimeType() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        AttributeInfo ts = findAttribute(schema, "createdTimestamp").orElseThrow();
        assertEquals(ZonedDateTime.class, ts.getType());
        assertFalse(ts.isCreateable());
        assertFalse(ts.isUpdateable());
    }

    @Test
    void containsGroups_multiValued_notReturnedByDefault() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{});
        AttributeInfo groups = findAttribute(schema, "groups").orElseThrow();
        assertTrue(groups.isMultiValued());
        assertFalse(groups.isReturnedByDefault());
    }

    @Test
    void customAttribute_singleValued() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{"department"});
        AttributeInfo dept = findAttribute(schema, "department").orElseThrow();
        assertFalse(dept.isMultiValued());
        assertFalse(dept.isRequired());
        assertTrue(dept.isUpdateable());
    }

    @Test
    void customAttribute_multivaluedSuffix_isMultiValued() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{"roles:multivalued"});
        AttributeInfo roles = findAttribute(schema, "roles").orElseThrow();
        assertTrue(roles.isMultiValued());
    }

    @Test
    void customAttribute_caseInsensitiveMultivaluedSuffix() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(new String[]{"tags:MULTIVALUED"});
        AttributeInfo tags = findAttribute(schema, "tags").orElseThrow();
        assertTrue(tags.isMultiValued());
    }

    @Test
    void multipleCustomAttributes() {
        ObjectClassInfo schema = KeycloakUserHandler.getUserSchema(
                new String[]{"dept", "tags:multivalued", "level"});
        assertTrue(findAttribute(schema, "dept").isPresent());
        assertTrue(findAttribute(schema, "tags").isPresent());
        assertTrue(findAttribute(schema, "level").isPresent());
    }
}
