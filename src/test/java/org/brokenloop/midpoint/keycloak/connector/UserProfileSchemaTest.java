package org.brokenloop.midpoint.keycloak.connector;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPConfig;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UserProfileSchemaTest {

    private static UPConfig profile(UPAttribute... attrs) {
        UPConfig config = new UPConfig();
        config.setAttributes(Arrays.asList(attrs));
        return config;
    }

    private static UPAttribute attr(String name, boolean multivalued) {
        UPAttribute a = new UPAttribute(name);
        a.setMultivalued(multivalued);
        return a;
    }

    private static Set<String> set(String[] values) {
        return new HashSet<>(Arrays.asList(values));
    }

    @Test
    void skipsBuiltIns() {
        UPConfig p = profile(attr("username", false), attr("email", false),
                attr("firstName", false), attr("lastName", false), attr("dept", false));
        assertEquals(Set.of("dept"), set(UserProfileSchema.merge(new String[]{}, p)));
    }

    @Test
    void skipsConnectorAttributes() {
        UPConfig p = profile(attr("realmRoles", false), attr("clientRoles", false),
                attr("federatedIdentities", false), attr("requiredActions", false),
                attr("groups", false), attr("dept", false));
        assertEquals(Set.of("dept"), set(UserProfileSchema.merge(new String[]{}, p)));
    }

    @Test
    void multivaluedFromProfile() {
        UPConfig p = profile(attr("dept", false), attr("tags", true));
        assertEquals(Set.of("dept", "tags:multivalued"), set(UserProfileSchema.merge(new String[]{}, p)));
    }

    @Test
    void explicitAttributeWins() {
        UPConfig p = profile(attr("tags", true));
        String[] merged = UserProfileSchema.merge(new String[]{"tags"}, p);
        assertEquals(Set.of("tags"), set(merged));
        assertEquals(1, merged.length);
    }

    @Test
    void keepsExplicitNotInProfile() {
        UPConfig p = profile(attr("dept", false));
        assertEquals(Set.of("extra:multivalued", "dept"),
                set(UserProfileSchema.merge(new String[]{"extra:multivalued"}, p)));
    }

    @Test
    void nullProfileReturnsExplicit() {
        String[] explicit = {"a", "b:multivalued"};
        assertArrayEquals(explicit, UserProfileSchema.merge(explicit, null));
    }
}
