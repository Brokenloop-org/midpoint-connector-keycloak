package jp.openstandia.connector.keycloak;

import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.Test;

import static jp.openstandia.connector.keycloak.ConnIdTestFixtures.findAttribute;
import static org.junit.jupiter.api.Assertions.*;

class ClientSchemaTest {

    @Test
    void objectClassType_isClient() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        assertEquals("client", schema.getType());
    }

    @Test
    void containsUid_notCreateable_notUpdateable() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        AttributeInfo uid = findAttribute(schema, Uid.NAME).orElseThrow();
        assertFalse(uid.isCreateable());
        assertFalse(uid.isUpdateable());
    }

    @Test
    void containsName_required_updateable() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        AttributeInfo name = findAttribute(schema, Name.NAME).orElseThrow();
        assertTrue(name.isRequired());
        assertTrue(name.isUpdateable());
    }

    @Test
    void containsProtocol_required_createable_notUpdateable() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        AttributeInfo protocol = findAttribute(schema, "protocol").orElseThrow();
        assertTrue(protocol.isRequired());
        assertTrue(protocol.isCreateable());
        assertFalse(protocol.isUpdateable());
    }

    @Test
    void booleanAttributes_correctType() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        String[] boolAttrs = {
                "publicClient", "standardFlowEnabled", "implicitFlowEnabled",
                "directAccessGrantsEnabled", "serviceAccountsEnabled", "bearerOnly",
                "authorizationServicesEnabled"
        };
        for (String attr : boolAttrs) {
            AttributeInfo info = findAttribute(schema, attr).orElseThrow(
                    () -> new AssertionError("Missing attribute: " + attr));
            assertEquals(Boolean.class, info.getType(), "Type mismatch for: " + attr);
        }
    }

    @Test
    void containsSecret_guardedStringType() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        AttributeInfo secret = findAttribute(schema, "secret").orElseThrow();
        assertEquals(GuardedString.class, secret.getType());
    }

    @Test
    void containsRedirectUris_multiValued() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        AttributeInfo redirectUris = findAttribute(schema, "redirectUris").orElseThrow();
        assertTrue(redirectUris.isMultiValued());
    }

    @Test
    void containsWebOrigins_multiValued() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        AttributeInfo webOrigins = findAttribute(schema, "webOrigins").orElseThrow();
        assertTrue(webOrigins.isMultiValued());
    }

    @Test
    void containsEnable() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        assertTrue(findAttribute(schema, OperationalAttributes.ENABLE_NAME).isPresent());
    }

    @Test
    void configuredAttributes_addedAsSingleValued() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{"myCustom"});
        AttributeInfo custom = findAttribute(schema, "myCustom").orElseThrow();
        assertFalse(custom.isMultiValued());
        assertFalse(custom.isRequired());
    }

    @Test
    void containsAttributes_multiValued() {
        ObjectClassInfo schema = KeycloakClientHandler.getClientSchema(new String[]{});
        AttributeInfo attrs = findAttribute(schema, "attributes").orElseThrow();
        assertTrue(attrs.isMultiValued());
    }
}
