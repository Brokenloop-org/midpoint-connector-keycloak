package org.brokenloop.midpoint.keycloak.connector.rest;

import java.util.Set;

import org.brokenloop.midpoint.keycloak.connector.RoleDiff;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Composites bypass the role ignore list: an ignored-name child is added and removed like any other. */
class CompositeOpsDiffTest {

    @Test
    void ignoredNameChildIsStillAdded() {
        AttributeDelta delta = AttributeDeltaBuilder.build("compositeRealmRoles", Set.of("offline_access", "role-a"), Set.of());
        RoleDiff d = CompositeOps.diff(Set.of(), delta);
        assertEquals(Set.of("offline_access", "role-a"), d.toAdd());
    }

    @Test
    void ignoredNameChildIsStillRemoved() {
        AttributeDelta delta = AttributeDeltaBuilder.build("compositeRealmRoles", Set.of(), Set.of("offline_access"));
        RoleDiff d = CompositeOps.diff(Set.of("offline_access", "role-a"), delta);
        assertEquals(Set.of("offline_access"), d.toRemove());
    }

    @Test
    void replaceIncludingIgnoredNames() {
        AttributeDeltaBuilder b = new AttributeDeltaBuilder();
        b.setName("compositeRealmRoles");
        b.addValueToReplace("uma_authorization");
        RoleDiff d = CompositeOps.diff(Set.of("offline_access"), b.build());
        assertEquals(Set.of("uma_authorization"), d.toAdd());
        assertEquals(Set.of("offline_access"), d.toRemove());
    }
}
