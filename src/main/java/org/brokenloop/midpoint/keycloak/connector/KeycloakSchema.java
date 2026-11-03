/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.keycloak.representations.userprofile.config.UPConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Schema for Keycloak objects.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakSchema {

    private static final Log LOG = Log.getLog(KeycloakSchema.class);

    private final KeycloakConfiguration configuration;
    private final KeycloakClient client;

    public String version;
    public int majorVersion;
    public int minorVersion;
    public int patchVersion;

    public final Schema schema;
    public final Map<String, AttributeInfo> userSchema;
    public final Map<String, AttributeInfo> groupSchema;
    public final Map<String, AttributeInfo> clientSchema;
    public final Map<String, AttributeInfo> clientRoleSchema;
    public final Map<String, AttributeInfo> realmRoleSchema;
    public final Map<String, AttributeInfo> organizationSchema;
    public final boolean organizationsAvailable;

    public KeycloakSchema(KeycloakConfiguration configuration, KeycloakClient client) {
        this.configuration = configuration;
        this.client = client;

        SchemaBuilder schemaBuilder = new SchemaBuilder(KeycloakConnector.class);

        ObjectClassInfo userSchemaInfo = KeycloakUserHandler.getUserSchema(getUserAttributes());
        schemaBuilder.defineObjectClass(userSchemaInfo);

        ObjectClassInfo groupSchemaInfo = KeycloakGroupHandler.getGroupSchema(getGroupAttributes());
        schemaBuilder.defineObjectClass(groupSchemaInfo);

        ObjectClassInfo clientSchemaInfo = KeycloakClientHandler.getClientSchema(getClientAttributes());
        schemaBuilder.defineObjectClass(clientSchemaInfo);

        ObjectClassInfo clientRoleSchemaInfo = KeycloakClientRoleHandler.getSchema(new String[]{});
        schemaBuilder.defineObjectClass(clientRoleSchemaInfo);

        ObjectClassInfo realmRoleSchemaInfo = KeycloakRealmRoleHandler.getSchema(new String[]{});
        schemaBuilder.defineObjectClass(realmRoleSchemaInfo);

        // Only expose the Organization object class if the server-level feature
        // is enabled and the target realm has organizationsEnabled=true.
        // Otherwise org operations would fail with cryptic 404s.
        this.organizationsAvailable = client.isFeatureEnabled("organization")
                && client.isRealmOrganizationsEnabled(configuration.getTargetRealmName());

        ObjectClassInfo organizationSchemaInfo = KeycloakOrganizationHandler.getSchema(new String[]{});
        if (organizationsAvailable) {
            schemaBuilder.defineObjectClass(organizationSchemaInfo);
        }

        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAttributesToGet(), SearchOp.class);
        schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildReturnDefaultAttributes(), SearchOp.class);

        schema = schemaBuilder.build();

        Map<String, AttributeInfo> userSchemaMap = new HashMap<>();
        for (AttributeInfo info : userSchemaInfo.getAttributeInfo()) {
            userSchemaMap.put(info.getName(), info);
        }

        Map<String, AttributeInfo> groupSchemaMap = new HashMap<>();
        for (AttributeInfo info : groupSchemaInfo.getAttributeInfo()) {
            groupSchemaMap.put(info.getName(), info);
        }

        Map<String, AttributeInfo> clientSchemaMap = new HashMap<>();
        for (AttributeInfo info : clientSchemaInfo.getAttributeInfo()) {
            clientSchemaMap.put(info.getName(), info);
        }

        Map<String, AttributeInfo> clientRoleSchemaMap = new HashMap<>();
        for (AttributeInfo info : clientRoleSchemaInfo.getAttributeInfo()) {
            clientRoleSchemaMap.put(info.getName(), info);
        }

        Map<String, AttributeInfo> realmRoleSchemaMap = new HashMap<>();
        for (AttributeInfo info : realmRoleSchemaInfo.getAttributeInfo()) {
            realmRoleSchemaMap.put(info.getName(), info);
        }

        Map<String, AttributeInfo> organizationSchemaMap = new HashMap<>();
        for (AttributeInfo info : organizationSchemaInfo.getAttributeInfo()) {
            organizationSchemaMap.put(info.getName(), info);
        }

        this.userSchema = Collections.unmodifiableMap(userSchemaMap);
        this.groupSchema = Collections.unmodifiableMap(groupSchemaMap);
        this.clientSchema = Collections.unmodifiableMap(clientSchemaMap);
        this.clientRoleSchema = Collections.unmodifiableMap(clientRoleSchemaMap);
        this.realmRoleSchema = Collections.unmodifiableMap(realmRoleSchemaMap);
        this.organizationSchema = Collections.unmodifiableMap(organizationSchemaMap);

        this.version = client.getVersion();

        parseVersion();
    }

    private void parseVersion() {
        try {
            String[] s = version.split("\\.");
            this.majorVersion = Integer.parseInt(s[0]);
            this.minorVersion = Integer.parseInt(s[1]);
            if (s[2].contains("-")) {
                String ps = s[2].substring(0, s[2].indexOf("-"));
                this.patchVersion = Integer.parseInt(ps);
            } else {
                this.patchVersion = Integer.parseInt(s[2]);
            }
        } catch (NumberFormatException | IndexOutOfBoundsException e) {
            throw new ConnectorException(String.format("Keycloak returns unexpected version number: %s", version));
        }
    }

    private String[] getUserAttributes() {
        String userAttributes = configuration.getUserAttributes();
        String[] explicit = withoutReserved(userAttributes != null ? userAttributes.split(",") : new String[]{},
                USER_RESERVED, "userAttributes");
        if (!configuration.isUserProfileSchemaEnabled()) {
            return explicit;
        }
        UPConfig profile = null;
        try {
            profile = client.getUserProfileConfig(configuration.getTargetRealmName());
        } catch (RuntimeException e) {
            LOG.error("Failed to read the user profile of realm {0} although userProfileSchemaEnabled is true; "
                    + "using the configured user attributes only. The service account probably lacks a "
                    + "realm-management role such as query-users or view-users: {1}",
                    configuration.getTargetRealmName(), e.getMessage());
        }
        return UserProfileSchema.merge(explicit, profile);
    }

    private String[] getGroupAttributes() {
        String groupAttributes = configuration.getGroupAttributes();
        if (groupAttributes != null) {
            return withoutReserved(groupAttributes.split(","), GROUP_RESERVED, "groupAttributes");
        }
        return new String[]{};
    }

    /** Attribute names the connector defines itself on the user object class. */
    private static final Set<String> USER_RESERVED = Set.of(
            KeycloakUserHandler.ATTR_EMAIL, KeycloakUserHandler.ATTR_EMAIL_VERIFIED,
            KeycloakUserHandler.ATTR_FIRST_NAME, KeycloakUserHandler.ATTR_LAST_NAME,
            KeycloakUserHandler.ATTR_CREATED_TIMESTAMP, KeycloakUserHandler.ATTR_REQUIRED_ACTIONS,
            KeycloakUserHandler.ATTR_GROUPS, KeycloakUserHandler.ATTR_REALM_ROLES,
            KeycloakUserHandler.ATTR_CLIENT_ROLES, KeycloakUserHandler.ATTR_FEDERATED_IDENTITIES);

    /** Attribute names the connector defines itself on the group object class. */
    private static final Set<String> GROUP_RESERVED = Set.of(
            KeycloakGroupHandler.ATTR_PATH, KeycloakGroupHandler.ATTR_PARENT_GROUP,
            KeycloakGroupHandler.ATTR_REALM_ROLES, KeycloakGroupHandler.ATTR_CLIENT_ROLES);

    /** Drops configured entries whose name is already defined by the connector, so the schema has no duplicates. */
    private static String[] withoutReserved(String[] entries, Set<String> reserved, String option) {
        List<String> kept = new ArrayList<>();
        for (String entry : entries) {
            String name = entry.contains(":") ? entry.substring(0, entry.indexOf(':')) : entry;
            if (reserved.contains(name)) {
                LOG.warn("Ignoring {0} entry \"{1}\": the connector already defines an attribute with that name",
                        option, entry);
                continue;
            }
            kept.add(entry);
        }
        return kept.toArray(new String[0]);
    }

    private String[] getClientAttributes() {
        String clientAttributes = configuration.getClientAttributes();
        if (clientAttributes != null) {
            return clientAttributes.split(",");
        }
        return new String[]{};
    }

    public boolean isUserSchema(Attribute attribute) {
        return userSchema.containsKey(attribute.getName());
    }

    public boolean isMultiValuedUserSchema(Attribute attribute) {
        return userSchema.get(attribute.getName()).isMultiValued();
    }

    public boolean isUserSchema(AttributeDelta delta) {
        return userSchema.containsKey(delta.getName());
    }

    public boolean isMultiValuedUserSchema(AttributeDelta delta) {
        return userSchema.get(delta.getName()).isMultiValued();
    }

    public AttributeInfo getUserSchema(String attributeName) {
        return userSchema.get(attributeName);
    }

    public boolean isGroupSchema(Attribute attribute) {
        return groupSchema.containsKey(attribute.getName());
    }

    public boolean isMultiValuedGroupSchema(Attribute attribute) {
        return groupSchema.get(attribute.getName()).isMultiValued();
    }

    public boolean isGroupSchema(AttributeDelta delta) {
        return groupSchema.containsKey(delta.getName());
    }

    public boolean isMultiValuedGroupSchema(AttributeDelta delta) {
        return groupSchema.get(delta.getName()).isMultiValued();
    }

    public AttributeInfo getGroupSchema(String attributeName) {
        return groupSchema.get(attributeName);
    }

    public boolean isClientSchema(Attribute attribute) {
        return clientSchema.containsKey(attribute.getName());
    }

    public boolean isMultiValuedClientSchema(Attribute attribute) {
        return clientSchema.get(attribute.getName()).isMultiValued();
    }

    public boolean isClientSchema(AttributeDelta delta) {
        return clientSchema.containsKey(delta.getName());
    }

    public boolean isMultiValuedClientSchema(AttributeDelta delta) {
        return clientSchema.get(delta.getName()).isMultiValued();
    }

    public AttributeInfo getClientSchema(String attributeName) {
        return clientSchema.get(attributeName);
    }
}
