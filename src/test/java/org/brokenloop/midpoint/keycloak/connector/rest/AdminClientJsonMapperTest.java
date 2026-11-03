package org.brokenloop.midpoint.keycloak.connector.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.RoleRepresentation;

import static org.junit.jupiter.api.Assertions.*;

/** The admin client's JSON mapper tolerates newer server fields and does not send nulls. */
class AdminClientJsonMapperTest {

    private static ObjectMapper mapper() {
        return KeycloakAdminRESTAdminClient.LENIENT_MAPPER_RESOLVER.getContext(RoleRepresentation.class);
    }

    @Test
    void ignoresUnknownPropertiesOnDeserialization() throws Exception {
        RoleRepresentation role = mapper().readValue(
                "{\"name\":\"role-a\",\"fieldFromANewerServer\":{\"x\":1}}", RoleRepresentation.class);
        assertEquals("role-a", role.getName());
    }

    @Test
    void omitsNullsOnSerialization() throws Exception {
        RoleRepresentation role = new RoleRepresentation();
        role.setName("role-a");
        String json = mapper().writeValueAsString(role);
        assertTrue(json.contains("\"name\":\"role-a\""), json);
        assertFalse(json.contains("null"), json);
        assertFalse(json.contains("description"), json);
    }
}
