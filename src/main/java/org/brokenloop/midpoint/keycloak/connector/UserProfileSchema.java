package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.common.logging.Log;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPConfig;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.*;

/**
 * Merges the attributes declared in a realm's Keycloak User Profile into the
 * explicitly configured user attributes, using the {@code name} /
 * {@code name:multivalued} format understood by {@link KeycloakUserHandler#getUserSchema(String[])}.
 */
final class UserProfileSchema {

    private static final Log LOGGER = Log.getLog(UserProfileSchema.class);

    private static final String MULTIVALUED = "multivalued";

    /** Attributes that are already defined by the connector's own user schema. */
    private static final Set<String> BUILT_IN = Set.of(
            ATTR_USERNAME, ATTR_EMAIL, ATTR_FIRST_NAME, ATTR_LAST_NAME,
            ATTR_REALM_ROLES, ATTR_CLIENT_ROLES, ATTR_FEDERATED_IDENTITIES,
            ATTR_REQUIRED_ACTIONS, ATTR_GROUPS);

    private UserProfileSchema() {
    }

    static String[] merge(String[] explicitUserAttributes, UPConfig profile) {
        if (profile == null) {
            return explicitUserAttributes;
        }

        // name -> multivalued, in insertion order
        Map<String, Boolean> merged = new LinkedHashMap<>();
        List<UPAttribute> profileAttributes = profile.getAttributes();
        if (profileAttributes != null) {
            for (UPAttribute attribute : profileAttributes) {
                String name = attribute.getName();
                if (BUILT_IN.contains(name)) {
                    if (!isCoreProfileAttribute(name)) {
                        LOGGER.warn("User profile attribute \"{0}\" collides with a built-in connector " +
                                "attribute and is ignored", name);
                    }
                    continue;
                }
                merged.put(name, attribute.isMultivalued());
            }
        }

        List<String> explicitNotInProfile = new ArrayList<>();
        for (String entry : explicitUserAttributes) {
            String name = entry.contains(":") ? entry.substring(0, entry.indexOf(':')) : entry;
            boolean multivalued = entry.contains(":")
                    && entry.substring(entry.indexOf(':') + 1).equalsIgnoreCase(MULTIVALUED);
            Boolean fromProfile = merged.remove(name);
            if (fromProfile == null) {
                explicitNotInProfile.add(entry);
                continue;
            }
            if (fromProfile != multivalued) {
                LOGGER.warn("User attribute \"{0}\" is configured as {1} but the user profile declares it as {2}; " +
                                "the explicit configuration wins",
                        name, multiplicity(multivalued), multiplicity(fromProfile));
            }
            explicitNotInProfile.add(entry);
        }

        if (!explicitNotInProfile.isEmpty() && profile.getUnmanagedAttributePolicy() == null) {
            LOGGER.warn("Unmanaged user attributes are disabled in the realm user profile; writes to explicitly " +
                    "configured attributes that are not declared in the profile will be rejected or dropped");
        }

        List<String> result = new ArrayList<>();
        for (Map.Entry<String, Boolean> e : merged.entrySet()) {
            result.add(e.getValue() ? e.getKey() + ":" + MULTIVALUED : e.getKey());
        }
        result.addAll(explicitNotInProfile);
        return result.toArray(new String[0]);
    }

    private static boolean isCoreProfileAttribute(String name) {
        return ATTR_USERNAME.equals(name) || ATTR_EMAIL.equals(name)
                || ATTR_FIRST_NAME.equals(name) || ATTR_LAST_NAME.equals(name);
    }

    private static String multiplicity(boolean multivalued) {
        return multivalued ? "multivalued" : "single-valued";
    }
}
