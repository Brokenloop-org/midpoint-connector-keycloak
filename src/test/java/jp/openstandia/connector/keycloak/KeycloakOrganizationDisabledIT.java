package jp.openstandia.connector.keycloak;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.junit.jupiter.api.*;

import java.util.HashSet;
import java.util.Set;

import static jp.openstandia.connector.keycloak.KeycloakOrganizationHandler.ORGANIZATION_OBJECT_CLASS;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the connector gracefully handles the case where the Organization
 * feature is unavailable: the object class is omitted from the schema, and
 * attempting to use it raises a clear error.
 */
class KeycloakOrganizationDisabledIT extends AbstractKeycloakIT {

    static final String REALM = "test-org-disabled";
    static KeycloakConnector connector;

    @BeforeAll
    static void setup() {
        // Create realm WITHOUT organizationsEnabled
        setupRealm(REALM, false);
        connector = newConnector(REALM);
    }

    @AfterAll
    static void teardown() {
        if (connector != null) connector.dispose();
        teardownRealm(REALM);
    }

    @Test
    void schema_omitsOrganizationObjectClass_whenRealmFlagDisabled() {
        Schema schema = connector.schema();
        ObjectClassInfo orgInfo = schema.findObjectClassInfo("organization");
        assertNull(orgInfo, "Organization object class should not be in schema when feature is unavailable");
    }

    @Test
    void create_organization_throwsClearError_whenRealmFlagDisabled() {
        Set<Attribute> attrs = new HashSet<>();
        attrs.add(new Name("forbidden-org"));

        InvalidAttributeValueException ex = assertThrows(InvalidAttributeValueException.class,
                () -> connector.create(ORGANIZATION_OBJECT_CLASS, attrs, null));
        assertTrue(ex.getMessage().contains("Organization"),
                "Error message should mention Organization. Got: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("organization") || ex.getMessage().contains("organizationsEnabled"),
                "Error message should mention how to enable. Got: " + ex.getMessage());
    }
}
