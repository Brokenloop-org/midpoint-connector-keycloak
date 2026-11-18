package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeycloakFilterTest {

    @Test
    void byUid_createsFilterWithUid() {
        Uid uid = new Uid("abc-123");
        KeycloakFilter filter = KeycloakFilter.By(uid);
        assertEquals(uid, filter.uid);
    }

    @Test
    void byUid_isByUid_returnsTrue() {
        KeycloakFilter filter = KeycloakFilter.By(new Uid("abc-123"));
        assertTrue(filter.isByUid());
    }

    @Test
    void byUid_isByName_returnsFalse() {
        KeycloakFilter filter = KeycloakFilter.By(new Uid("abc-123"));
        assertFalse(filter.isByName());
    }

    @Test
    void byUid_nameIsNull() {
        KeycloakFilter filter = KeycloakFilter.By(new Uid("abc-123"));
        assertNull(filter.name);
    }

    @Test
    void byName_createsFilterWithName() {
        Name name = new Name("admin");
        KeycloakFilter filter = KeycloakFilter.By(name);
        assertEquals(name, filter.name);
    }

    @Test
    void byName_isByName_returnsTrue() {
        KeycloakFilter filter = KeycloakFilter.By(new Name("admin"));
        assertTrue(filter.isByName());
    }

    @Test
    void byName_isByUid_returnsFalse() {
        KeycloakFilter filter = KeycloakFilter.By(new Name("admin"));
        assertFalse(filter.isByUid());
    }

    @Test
    void byName_uidIsNull() {
        KeycloakFilter filter = KeycloakFilter.By(new Name("admin"));
        assertNull(filter.uid);
    }
}
