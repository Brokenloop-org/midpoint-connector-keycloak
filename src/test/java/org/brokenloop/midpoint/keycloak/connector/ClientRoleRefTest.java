package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ClientRoleRefTest {

    @Test
    void parsesAndFormatsRoundTrip() {
        ClientRoleRef ref = ClientRoleRef.parse("client-uuid/role-a");
        assertEquals("client-uuid", ref.clientUuid());
        assertEquals("role-a", ref.roleName());
        assertEquals("client-uuid/role-a", ref.format());
    }

    @Test
    void rejectsMalformedReferences() {
        for (String bad : new String[]{"/r", "u/", "", "no-slash", "a/b/c", "/"}) {
            assertThrows(InvalidAttributeValueException.class, () -> ClientRoleRef.parse(bad), "'" + bad + "'");
        }
        assertThrows(InvalidAttributeValueException.class, () -> ClientRoleRef.parse(null));
    }
}
