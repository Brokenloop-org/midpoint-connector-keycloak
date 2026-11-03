package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RoleMappingsNullFilteringTest {

    @Test
    void withoutIgnoredDropsNullElementsAndIgnoredValues() {
        Set<String> result = RoleMappings.withoutIgnored(Arrays.asList("role-a", null, "role-b", "role-c", null), Set.of("role-c"));
        assertEquals(Set.of("role-a", "role-b"), result);
    }

    @Test
    void withoutIgnoredAcceptsNullCollectionAndNullIgnoreSet() {
        assertTrue(RoleMappings.withoutIgnored(null, Set.of()).isEmpty());
        assertEquals(Set.of("role-a"), RoleMappings.withoutIgnored(Arrays.asList("role-a", null), null));
    }

    @Test
    void diffSkipsNullValuesInAddRemoveAndReplace() {
        AttributeDelta addRemove = AttributeDeltaBuilder.build("roles",
                Arrays.asList("role-b", null), Arrays.asList(null, "role-a"));
        RoleDiff d = RoleMappings.diff(Set.of("role-a"), addRemove, Set.of());
        assertEquals(Set.of("role-b"), d.toAdd());
        assertEquals(Set.of("role-a"), d.toRemove());

        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("roles");
        b.addValueToReplace("role-b", null);
        RoleDiff r = RoleMappings.diff(Set.of("role-a"), b.build(), Set.of());
        assertEquals(Set.of("role-b"), r.toAdd());
        assertEquals(Set.of("role-a"), r.toRemove());
    }
}
