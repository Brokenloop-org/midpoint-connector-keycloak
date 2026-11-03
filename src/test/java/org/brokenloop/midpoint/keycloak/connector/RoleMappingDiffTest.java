package org.brokenloop.midpoint.keycloak.connector;

import java.util.Set;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RoleMappingDiffTest {

    private static AttributeDelta addRemove(Set<String> add, Set<String> remove) {
        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("roles");
        if (add != null) {
            b.addValueToAdd(add.toArray());
        }
        if (remove != null) {
            b.addValueToRemove(remove.toArray());
        }
        return b.build();
    }

    private static AttributeDelta replace(Set<String> values) {
        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("roles");
        b.addValueToReplace(values.toArray());
        return b.build();
    }

    @Test
    void addOnlyNewValues() {
        RoleDiff d = RoleMappings.diff(Set.of("a"), addRemove(Set.of("a", "b"), null), Set.of());
        assertEquals(Set.of("b"), d.toAdd());
        assertEquals(Set.of(), d.toRemove());
    }

    @Test
    void removeOnlyPresentValues() {
        RoleDiff d = RoleMappings.diff(Set.of("a"), addRemove(null, Set.of("a", "c")), Set.of());
        assertEquals(Set.of("a"), d.toRemove());
        assertEquals(Set.of(), d.toAdd());
    }

    @Test
    void replaceComputesBothSides() {
        RoleDiff d = RoleMappings.diff(Set.of("a", "b"), replace(Set.of("b", "c")), Set.of());
        assertEquals(Set.of("c"), d.toAdd());
        assertEquals(Set.of("a"), d.toRemove());
    }

    @Test
    void replaceKeepsIgnoredRoles() {
        RoleDiff d = RoleMappings.diff(Set.of("a", "default-roles-r"), replace(Set.of("c")),
                Set.of("default-roles-r"));
        assertEquals(Set.of("c"), d.toAdd());
        assertEquals(Set.of("a"), d.toRemove());
    }

    @Test
    void addIgnoredIsDropped() {
        RoleDiff d = RoleMappings.diff(Set.of(), addRemove(Set.of("offline_access"), null),
                Set.of("offline_access"));
        assertTrue(d.toAdd().isEmpty());
        assertTrue(d.toRemove().isEmpty());
    }

    @Test
    void clientRoleRefRoundTrip() throws Exception {
        assertEquals("u-1/r", ClientRoleRef.parse("u-1/r").format());
    }

    @Test
    void clientRoleRefRejectsMalformed() {
        assertThrows(InvalidAttributeValueException.class, () -> ClientRoleRef.parse("x"));
        assertThrows(InvalidAttributeValueException.class, () -> ClientRoleRef.parse("a/b/c"));
    }

    @Test
    void addAndRemoveInOneDelta() {
        RoleDiff d = RoleMappings.diff(Set.of("a", "b"), addRemove(Set.of("c"), Set.of("a")), Set.of());
        assertEquals(Set.of("c"), d.toAdd());
        assertEquals(Set.of("a"), d.toRemove());
    }

    @Test
    void replaceWithEmptyRemovesEverythingExceptIgnored() {
        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("roles");
        b.addValueToReplace();
        RoleDiff d = RoleMappings.diff(Set.of("a", "b", "offline_access"), b.build(), Set.of("offline_access"));
        assertEquals(Set.of(), d.toAdd());
        assertEquals(Set.of("a", "b"), d.toRemove());
    }

    @Test
    void removingAnIgnoredRoleIsDropped() {
        RoleDiff d = RoleMappings.diff(Set.of("a", "offline_access"), addRemove(null, Set.of("offline_access")),
                Set.of("offline_access"));
        assertTrue(d.toRemove().isEmpty());
    }
}
