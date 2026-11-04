package org.brokenloop.midpoint.keycloak.connector;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakSchemaReservedTest {

    @Test
    void userEntriesCollidingWithBuiltInAttributesAreSkipped() {
        String[] kept = KeycloakSchema.withoutReserved(
                new String[]{"dept", "realmRoles", "federatedIdentities:string", "email", "requiredActions", "tags:multi"},
                KeycloakSchema.USER_RESERVED, "userAttributes");
        assertArrayEquals(new String[]{"dept", "tags:multi"}, kept);
    }

    @Test
    void groupEntriesCollidingWithBuiltInAttributesAreSkipped() {
        String[] kept = KeycloakSchema.withoutReserved(
                new String[]{"clientRoles", "owner", "path:string", "realmRoles"},
                KeycloakSchema.GROUP_RESERVED, "groupAttributes");
        assertArrayEquals(new String[]{"owner"}, kept);
    }

    @Test
    void entriesWithoutCollisionAreKeptInOrder() {
        String[] in = {"b", "a:multi", "c"};
        assertArrayEquals(in, KeycloakSchema.withoutReserved(in, KeycloakSchema.USER_RESERVED, "userAttributes"));
    }

    @Test
    void emptyInputGivesEmptyOutput() {
        assertEquals(0, KeycloakSchema.withoutReserved(new String[]{}, KeycloakSchema.USER_RESERVED, "userAttributes").length);
    }
}
