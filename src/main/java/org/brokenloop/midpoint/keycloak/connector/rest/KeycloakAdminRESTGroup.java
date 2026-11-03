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
package org.brokenloop.midpoint.keycloak.connector.rest;

import org.brokenloop.midpoint.keycloak.connector.KeycloakClient;
import org.brokenloop.midpoint.keycloak.connector.KeycloakConfiguration;
import org.brokenloop.midpoint.keycloak.connector.KeycloakSchema;
import org.brokenloop.midpoint.keycloak.connector.RoleDiff;
import org.brokenloop.midpoint.keycloak.connector.RoleMappings;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.representations.idm.GroupRepresentation;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakGroupHandler.*;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakUtils.*;
import static org.brokenloop.midpoint.keycloak.connector.rest.KeycloakRESTUtils.checkCreateResult;

/**
 * Keycloak client implementation for group object which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTGroup implements KeycloakClient.Group {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTGroup.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private Keycloak adminClient;

    public KeycloakAdminRESTGroup(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private GroupsResource groups(String realmName) {
        return realm(realmName).groups();
    }

    @Override
    public Uid createGroup(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException {
        // Extract the parent group id (if any) before building the representation.
        // KC silently ignores parentId on the create payload, so nesting requires
        // the subGroup() endpoint on the parent.
        String parentId = null;
        Set<String> ignoredRoles = configuration.ignoredRolesResolved();
        Set<String> addRealmRoles = new LinkedHashSet<>();
        Set<String> addClientRoles = new LinkedHashSet<>();
        Set<Attribute> groupAttributes = new HashSet<>();
        for (Attribute attr : createAttributes) {
            if (attr.getName().equals(ATTR_PARENT_GROUP)) {
                parentId = AttributeUtil.getAsStringValue(attr);
                groupAttributes.add(attr);
            } else if (attr.getName().equals(ATTR_REALM_ROLES) || attr.getName().equals(ATTR_CLIENT_ROLES)) {
                Set<String> target = attr.getName().equals(ATTR_REALM_ROLES) ? addRealmRoles : addClientRoles;
                if (attr.getValue() != null) {
                    attr.getValue().stream().filter(Objects::nonNull).map(Object::toString).forEach(target::add);
                }
            } else {
                groupAttributes.add(attr);
            }
        }
        addRealmRoles = RoleMappings.withoutIgnored(addRealmRoles, ignoredRoles);
        addClientRoles = RoleMappings.withoutIgnored(addClientRoles, ignoredRoles);

        // Validate the roles up-front so an unknown role does not leave a half-created group behind.
        RealmResource realm = realm(realmName);
        RoleMappingOps.requireExisting(realm, addRealmRoles, addClientRoles);

        GroupRepresentation rep = toGroupRep(schema, groupAttributes);

        Response res;
        if (parentId != null) {
            res = groups(realmName).group(parentId).subGroup(rep);
        } else {
            res = groups(realmName).add(rep);
        }

        String uuid = checkCreateResult(res, "createGroup");

        if (!addRealmRoles.isEmpty() || !addClientRoles.isEmpty()) {
            RoleMappingResource rm = groups(realmName).group(uuid).roles();
            RoleMappingOps.applyRealm(realm, rm, new RoleDiff(addRealmRoles, Set.of()));
            RoleMappingOps.applyClient(realm, rm, new RoleDiff(addClientRoles, Set.of()));
        }

        return new Uid(uuid, new Name(rep.getName()));
    }

    protected GroupRepresentation toGroupRep(KeycloakSchema schema, Set<Attribute> attributes) {
        GroupRepresentation newGroup = new GroupRepresentation();

        for (Attribute attr : attributes) {
            // parentId is extracted up-front by createGroup, not stored on the rep.
            if (attr.getName().equals(ATTR_PARENT_GROUP)) {
                continue;
            }

            if (attr.getName().equals(Name.NAME)) {
                newGroup.setName(AttributeUtil.getAsStringValue(attr));

            } else {
                if (!schema.isGroupSchema(attr)) {
                    throw new InvalidAttributeValueException(String.format("Keycloak doesn't support to set '%s' attribute of Group",
                            attr.getName()));
                }
                if (schema.isMultiValuedGroupSchema(attr)) {
                    Map<String, List<String>> attrs = newGroup.getAttributes();
                    if (attrs == null) {
                        attrs = new HashMap<>();
                    }
                    attrs.put(attr.getName(), attr.getValue().stream().map(Object::toString).collect(Collectors.toList()));

                } else {
                    newGroup.singleAttribute(attr.getName(), AttributeUtil.getStringValue(attr));
                }
            }
        }

        return newGroup;
    }

    @Override
    public void updateGroup(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        GroupsResource resource = groups(realmName);
        GroupRepresentation current;
        String newParentGroupId = null;
        AttributeDelta realmRolesDelta = null;
        AttributeDelta clientRolesDelta = null;
        RoleDiff realmDiff = null;
        RoleDiff clientDiff = null;

        try {
            GroupResource group = resource.group(uid.getUidValue());
            current = group.toRepresentation();

            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(Uid.NAME)) {
                    // Keycloak doesn't support to modify 'id'
                    invalidSchema(delta.getName());

                } else if (delta.getName().equals(Name.NAME)) {
                    current.setName(AttributeDeltaUtil.getAsStringValue(delta));

                } else if (delta.getName().equals(ATTR_PARENT_GROUP)) {
                    newParentGroupId = AttributeDeltaUtil.getAsStringValue(delta);

                } else if (delta.getName().equals(ATTR_REALM_ROLES)) {
                    realmRolesDelta = delta;

                } else if (delta.getName().equals(ATTR_CLIENT_ROLES)) {
                    clientRolesDelta = delta;

                } else if (schema.isGroupSchema(delta)) {
                    if (schema.isMultiValuedGroupSchema(delta)) {
                        Map<String, List<String>> attrs = current.getAttributes();
                        if (attrs == null) {
                            attrs = new HashMap();
                        }
                        List<String> values = attrs.getOrDefault(delta.getName(), new ArrayList<>());
                        attrs.put(delta.getName(), values);

                        if (delta.getValuesToAdd() != null) {
                            for (Object v : delta.getValuesToAdd()) {
                                // TODO support more types
                                values.add(v.toString());
                            }
                        }

                        if (delta.getValuesToRemove() != null) {
                            for (Object v : delta.getValuesToRemove()) {
                                // TODO support more types
                                values.remove(v.toString());
                            }
                        }

                        current.setAttributes(attrs);

                    } else {
                        // TODO support more types
                        current.singleAttribute(delta.getName(), AttributeDeltaUtil.getStringValue(delta));
                    }

                } else {
                    invalidSchema(delta.getName());
                }
            }

            // Validate the role adds before the first write so a bad role does not leave a half-applied update.
            if (realmRolesDelta != null || clientRolesDelta != null) {
                Set<String> ignoredRoles = configuration.ignoredRolesResolved();
                RoleMappingResource rm = group.roles();
                if (realmRolesDelta != null) {
                    realmDiff = RoleMappings.diff(RoleMappingOps.readRealm(rm, ignoredRoles), realmRolesDelta, ignoredRoles);
                }
                if (clientRolesDelta != null) {
                    clientDiff = RoleMappings.diff(RoleMappingOps.readClient(rm, ignoredRoles), clientRolesDelta, ignoredRoles);
                }
                RoleMappingOps.requireExisting(realm(realmName),
                        realmDiff == null ? Set.of() : realmDiff.toAdd(),
                        clientDiff == null ? Set.of() : clientDiff.toAdd());
            }

            // TODO Optimize update if no diff
            group.update(current);

        } catch (NotFoundException e) {
            LOGGER.warn("Not found group when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, GROUP_OBJECT_CLASS);
        }

        // We need to call another API to add/remove parent group for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Keycloak data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.

        if (isTopGroup(current)) {
            if (newParentGroupId == null) {
                // From top => top
                // Do nothing!!
            } else {
                // From top => sub
                groups(realmName).group(newParentGroupId).subGroup(current);
            }
        } else {
            if (newParentGroupId == null) {
                // From sub => top level
                groups(realmName).add(current);
            } else {
                // From sub => sub with different parent
                groups(realmName).group(newParentGroupId).subGroup(current);
            }
        }

        if (realmDiff != null || clientDiff != null) {
            RoleMappingResource rm = groups(realmName).group(uid.getUidValue()).roles();
            RealmResource realm = realm(realmName);
            if (realmDiff != null) {
                RoleMappingOps.applyRealm(realm, rm, realmDiff);
            }
            if (clientDiff != null) {
                RoleMappingOps.applyClient(realm, rm, clientDiff);
            }
        }
    }

    private boolean isTopGroup(GroupRepresentation rep) {
        String path = rep.getPath();
        long count = path.chars().filter(ch -> ch == '/').count();
        return count == 1;
    }

    @Override
    public void deleteGroup(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException {
        try {
            groups(realmName).group(uid.getUidValue()).remove();

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found group when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, GROUP_OBJECT_CLASS);
        }
    }

    @Override
    public void getGroups(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                          Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        GroupsResource groups = groups(realmName);

        Map<String, Long> countMap = groups.count();
        Long count = countMap.get("count");

        int start = 0;
        int total = 0;

        while (total < count) {
            List<GroupRepresentation> results = groups.groups("", start, queryPageSize, true);

            if (results.size() == 0) {
                break;
            }

            for (GroupRepresentation rep : results) {
                if (!handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize))) {
                    KeycloakRESTUtils.signalAllResultsReturned(handler);
                    return;
                }
            }

            total += results.size();
            start += results.size();
        }

        KeycloakRESTUtils.signalAllResultsReturned(handler);
    }


    @Override
    public void getGroup(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                         Set<String> attributesToGet, int queryPageSize) {
        try {
            GroupRepresentation rep = groups(realmName).group(uid.getUidValue()).toRepresentation();

            if (rep == null) {
                LOGGER.warn("[{0}] Unknown groupId: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
                return;
            }

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            // Don't throw UnknownUidException
            // The executeQuery should not indicate any error in this case. It should not throw any exception.
            // MidPoint will see empty result set and it will figure out that there is no such object.
            LOGGER.warn("[{0}] Unknown groupId: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
            return;
        }
    }

    @Override
    public void getGroup(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                         Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        GroupsResource groups = groups(realmName);

        Map<String, Long> countMap = groups.count();
        Long count = countMap.get("count");

        int start = 0;
        int total = 0;

        while (total < count) {
            // KC's groups(search, first, max, briefRepresentation) takes max=page size,
            // not an end index. Pass queryPageSize directly.
            List<GroupRepresentation> results = groups.groups(name.getNameValue(), start, queryPageSize, true);

            if (results.size() == 0) {
                break;
            }

            for (GroupRepresentation rep : results) {
                if (rep.getName() != null && rep.getName().equalsIgnoreCase(name.getNameValue())) {
                    // Found
                    handler.handle(toConnectorObject(schema, realmName, rep, attributesToGet, allowPartialAttributeValues, queryPageSize));
                    return;
                }
            }

            total += results.size();
            start += results.size();
        }

        // NotFound
        LOGGER.warn("[{0}] Unknown group: {1}", instanceName, name.getNameValue());
    }


    private ConnectorObject toConnectorObject(KeycloakSchema schema, String realmName, GroupRepresentation rep,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues, int queryPageSize) {
        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(GROUP_OBJECT_CLASS)
                // Always returns "id"
                .setUid(rep.getId())
                // Always returns "name"
                .setName(rep.getName());

        builder.addAttribute(ATTR_PATH, rep.getPath());

        Map<String, List<String>> attributes = rep.getAttributes();
        if (attributes != null) {
            for (Map.Entry<String, List<String>> entry : rep.getAttributes().entrySet()) {
                String a = entry.getKey();
                AttributeInfo attributeInfo = schema.getGroupSchema(a);

                if (attributeInfo == null) {
                    LOGGER.ok("[{0}] Ignored. \"{1}\" is not defined in the group schema.", instanceName, a);
                    continue;
                }

                if (shouldReturn(attributesToGet, attributeInfo.getName())) {
                    builder.addAttribute(toConnectorAttribute(attributeInfo, entry));
                }
            }
        }

        if (allowPartialAttributeValues) {
            // Suppress fetching groups
            LOGGER.ok("[{0}] Suppress fetching parent group because return partial attribute values is requested", instanceName);

            AttributeBuilder ab = new AttributeBuilder();
            ab.setName(ATTR_PARENT_GROUP).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab.addValue(Collections.emptyList());
            builder.addAttribute(ab.build());
        } else {
            if (attributesToGet == null) {
                // Suppress fetching groups default
                LOGGER.ok("[{0}] Suppress fetching parent group because returned by default is true", instanceName);

            } else if (shouldReturn(attributesToGet, ATTR_PARENT_GROUP)) {
                // Use parentId field directly (available since KC 24)
                // instead of parsing the path and searching for the parent group
                String parentId = rep.getParentId();
                if (parentId != null) {
                    builder.addAttribute(ATTR_PARENT_GROUP, parentId);
                }
            }
        }

        addRoleMappings(builder, realmName, rep, attributesToGet, allowPartialAttributeValues);

        return builder.build();
    }

    private void addRoleMappings(ConnectorObjectBuilder builder, String realmName, GroupRepresentation group,
                                 Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        for (String attrName : new String[]{ATTR_REALM_ROLES, ATTR_CLIENT_ROLES}) {
            if (allowPartialAttributeValues) {
                AttributeBuilder ab = new AttributeBuilder();
                ab.setName(attrName).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
                ab.addValue(Collections.emptyList());
                builder.addAttribute(ab.build());

            } else if (attributesToGet != null && shouldReturn(attributesToGet, attrName)) {
                Set<String> ignoredRoles = configuration.ignoredRolesResolved();
                RoleMappingResource rm = groups(realmName).group(group.getId()).roles();
                Set<String> values = attrName.equals(ATTR_REALM_ROLES)
                        ? RoleMappingOps.readRealm(rm, ignoredRoles)
                        : RoleMappingOps.readClient(rm, ignoredRoles);
                builder.addAttribute(attrName, new ArrayList<>(values));
            }
        }
    }

}
