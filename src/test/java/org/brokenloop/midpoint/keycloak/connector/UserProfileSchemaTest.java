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

    @Test
    void warnsWhenExplicitAttributeMissingFromProfileAndPolicyNull() {
        UPConfig p = profile(attr("dept", false));
        assertTrue(UserProfileSchema.warnsAboutUnmanagedWrites(new String[]{"dept", "extra"}, p));
    }

    @Test
    void noWarningWhenEveryExplicitAttributeIsDeclared() {
        UPConfig p = profile(attr("dept", false), attr("tags", true));
        assertFalse(UserProfileSchema.warnsAboutUnmanagedWrites(new String[]{"dept", "tags:multivalued"}, p));
    }

    @Test
    void noWarningWhenUnmanagedPolicySet() {
        UPConfig p = profile(attr("dept", false));
        p.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
        assertFalse(UserProfileSchema.warnsAboutUnmanagedWrites(new String[]{"extra"}, p));
    }

    @Test
    void reportsExplicitSingleValuedAgainstMultivaluedProfileAttribute() {
        UPConfig p = profile(attr("tags", true));
        assertEquals(java.util.List.of("tags"), UserProfileSchema.multiplicityConflicts(new String[]{"tags"}, p));
        // explicit wins: the merged schema keeps the explicit single-valued entry
        assertArrayEquals(new String[]{"tags"}, UserProfileSchema.merge(new String[]{"tags"}, p));
    }

    @Test
    void reportsExplicitMultivaluedAgainstSingleValuedProfileAttribute() {
        UPConfig p = profile(attr("dept", false));
        assertEquals(java.util.List.of("dept"),
                UserProfileSchema.multiplicityConflicts(new String[]{"dept:multivalued"}, p));
        assertArrayEquals(new String[]{"dept:multivalued"},
                UserProfileSchema.merge(new String[]{"dept:multivalued"}, p));
    }

    @Test
    void noMultiplicityConflictWhenTheyAgreeOrTheProfileIsSilent() {
        UPConfig p = profile(attr("dept", false), attr("tags", true));
        assertTrue(UserProfileSchema.multiplicityConflicts(
                new String[]{"dept", "tags:multivalued", "extra:multivalued"}, p).isEmpty());
        assertTrue(UserProfileSchema.multiplicityConflicts(new String[]{"dept"}, null).isEmpty());
    }
}
