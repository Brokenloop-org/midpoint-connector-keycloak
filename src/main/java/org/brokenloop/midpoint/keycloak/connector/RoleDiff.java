package org.brokenloop.midpoint.keycloak.connector;

import java.util.Set;

/**
 * Values to add and to remove to reach the requested state.
 */
public record RoleDiff(Set<String> toAdd, Set<String> toRemove) {
}
