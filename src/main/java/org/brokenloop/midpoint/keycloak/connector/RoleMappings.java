package org.brokenloop.midpoint.keycloak.connector;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.identityconnectors.framework.common.objects.AttributeDelta;

/**
 * Pure helpers for role-mapping attributes: reference codec, ignore list and delta diffing.
 */
public final class RoleMappings {

    private RoleMappings() {
    }

    public static RoleDiff diff(Set<String> current, AttributeDelta delta, Set<String> ignored) {
        Set<String> cur = withoutIgnored(current, ignored);
        Set<String> toAdd = new LinkedHashSet<>();
        Set<String> toRemove = new LinkedHashSet<>();

        List<Object> replace = delta.getValuesToReplace();
        if (replace != null) {
            Set<String> wanted = withoutIgnored(strings(replace), ignored);
            for (String v : wanted) {
                if (!cur.contains(v)) {
                    toAdd.add(v);
                }
            }
            for (String v : cur) {
                if (!wanted.contains(v)) {
                    toRemove.add(v);
                }
            }
            return new RoleDiff(toAdd, toRemove);
        }

        if (delta.getValuesToAdd() != null) {
            for (String v : withoutIgnored(strings(delta.getValuesToAdd()), ignored)) {
                if (!cur.contains(v)) {
                    toAdd.add(v);
                }
            }
        }
        if (delta.getValuesToRemove() != null) {
            for (String v : withoutIgnored(strings(delta.getValuesToRemove()), ignored)) {
                if (cur.contains(v)) {
                    toRemove.add(v);
                }
            }
        }
        return new RoleDiff(toAdd, toRemove);
    }

    public static Set<String> withoutIgnored(Collection<String> values, Set<String> ignored) {
        Set<String> result = new LinkedHashSet<>();
        if (values == null) {
            return result;
        }
        for (String v : values) {
            if (v != null && (ignored == null || !ignored.contains(v))) {
                result.add(v);
            }
        }
        return result;
    }

    private static List<String> strings(List<Object> values) {
        return values.stream().map(String::valueOf).toList();
    }
}
