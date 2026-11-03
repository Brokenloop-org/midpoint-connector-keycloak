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

import org.brokenloop.midpoint.keycloak.connector.FederatedIdentityCodec;
import org.brokenloop.midpoint.keycloak.connector.KeycloakClient;
import org.brokenloop.midpoint.keycloak.connector.KeycloakConfiguration;
import org.brokenloop.midpoint.keycloak.connector.KeycloakSchema;
import org.brokenloop.midpoint.keycloak.connector.KeycloakUtils;
import org.brokenloop.midpoint.keycloak.connector.RoleDiff;
import org.brokenloop.midpoint.keycloak.connector.RoleMappings;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.*;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakUtils.*;
import static org.brokenloop.midpoint.keycloak.connector.rest.KeycloakRESTUtils.checkCreateResult;
import static org.brokenloop.midpoint.keycloak.connector.rest.KeycloakRESTUtils.checkDeleteResult;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;

/**
 * Keycloak client implementation for user object which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTUser implements KeycloakClient.User {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTUser.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private Keycloak adminClient;

    public KeycloakAdminRESTUser(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private UsersResource users(String realmName) {
        return realm(realmName).users();
    }

    @Override
    public Uid createUser(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes)
            throws AlreadyExistsException {
        Set<String> ignoredRoles = configuration.resolveIgnoredRoles();
        Set<String> addRealmRoles = new LinkedHashSet<>();
        Set<String> addClientRoles = new LinkedHashSet<>();
        Set<Attribute> userAttributes = new HashSet<>();
        Attribute federatedIdentities = null;
        for (Attribute attr : createAttributes) {
            if (attr.getName().equals(ATTR_FEDERATED_IDENTITIES)) {
                federatedIdentities = attr;
            } else if (attr.getName().equals(ATTR_REALM_ROLES) || attr.getName().equals(ATTR_CLIENT_ROLES)) {
                Set<String> target = attr.getName().equals(ATTR_REALM_ROLES) ? addRealmRoles : addClientRoles;
                if (attr.getValue() != null) {
                    attr.getValue().stream().filter(Objects::nonNull).map(Object::toString).forEach(target::add);
                }
            } else {
                userAttributes.add(attr);
            }
        }

        // Validate roles and links before creating the user so a bad value does not leave a half-created user behind.
        addRealmRoles = RoleMappings.withoutIgnored(addRealmRoles, ignoredRoles);
        addClientRoles = RoleMappings.withoutIgnored(addClientRoles, ignoredRoles);
        RoleMappingOps.requireExisting(realm(realmName), addRealmRoles, addClientRoles);

        // Validate the links before creating the user so a bad link does not leave a half-created user behind.
        List<FederatedIdentityRepresentation> addLinks = FederatedIdentityOps.parseAndValidate(
                realm(realmName), federatedIdentities == null ? null : federatedIdentities.getValue());
        FederatedIdentityOps.requireNotHeldByOther(realm(realmName), addLinks, null);

        UserRepresentation newUser = toUserRep(schema, userAttributes);

        CredentialRepresentation credential = null;
        if (configuration.isPasswordResetAPIEnabled()) {
            List<CredentialRepresentation> credentials = newUser.getCredentials();
            if (credentials != null && credentials.size() == 1) {
                credential = credentials.get(0);
            }
            // Need to remove credentials when using password reset API for setting the password.
            newUser.setCredentials(null);
        }

        List<String> addGroupIds = newUser.getGroups();
        // Remove groups intentionally because keycloak expects group path list
        newUser.setGroups(null);

        Response res = users(realmName).create(newUser);

        String uuid = checkCreateResult(res, "createUser");

        // We need to call another API to update password and add/remove group for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Keycloak data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.

        updatePassword(realmName, uuid, credential, true);

        // Adding groups when creating a user is supported from 9.0.2.
        // https://github.com/keycloak/keycloak/pull/6886
        // But it requires group path list. So we don't use this API.
        // That's why we call another API here.
        if (addGroupIds != null) {
            for (String groupId : addGroupIds) {
                try {
                    users(realmName).get(uuid).joinGroup(groupId);
                } catch (NotFoundException e) {
                    LOGGER.warn("The group is not found already. Skipping join the user. groupId: {0}, userId: {1}, username: {2}",
                            groupId, uuid, newUser.getUsername());
                }
            }
        }

        if (!addRealmRoles.isEmpty() || !addClientRoles.isEmpty()) {
            RoleMappingResource rm = users(realmName).get(uuid).roles();
            RealmResource realm = realm(realmName);
            RoleMappingOps.applyRealm(realm, rm, new RoleDiff(addRealmRoles, Set.of()));
            RoleMappingOps.applyClient(realm, rm, new RoleDiff(addClientRoles, Set.of()));
        }

        if (!addLinks.isEmpty()) {
            FederatedIdentityOps.add(users(realmName).get(uuid), addLinks);
        }

        return new Uid(uuid, new Name(newUser.getUsername()));
    }

    protected UserRepresentation toUserRep(KeycloakSchema schema, Set<Attribute> attributes) {
        UserRepresentation newUser = new UserRepresentation();

        for (Attribute attr : attributes) {
            if (attr.getName().equals(Name.NAME)) {
                newUser.setUsername(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ENABLE_NAME)) {
                newUser.setEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                List<CredentialRepresentation> credentials = new ArrayList<>();
                GuardedString password = AttributeUtil.getGuardedStringValue(attr);
                password.access(a -> {
                    String clearPassword = String.valueOf(a);
                    CredentialRepresentation passwordRep = new CredentialRepresentation();
                    passwordRep.setType(CredentialRepresentation.PASSWORD);
                    passwordRep.setTemporary(Boolean.FALSE);
                    passwordRep.setValue(clearPassword);

                    credentials.add(passwordRep);
                });
                newUser.setCredentials(credentials);

            } else if (attr.getName().equals(ATTR_EMAIL)) {
                newUser.setEmail(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_EMAIL_VERIFIED)) {
                newUser.setEmailVerified(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_FIRST_NAME)) {
                newUser.setFirstName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_LAST_NAME)) {
                newUser.setLastName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_REQUIRED_ACTIONS)) {
                List<String> actions = attr.getValue() == null ? new ArrayList<>()
                        : attr.getValue().stream().filter(Objects::nonNull).map(Object::toString)
                                .collect(Collectors.toList());
                newUser.setRequiredActions(actions);

            } else if (attr.getName().equals(ATTR_GROUPS)) {
                // Keycloak expects the group list as group path list.
                // Because we set group id list here, we cant't use it for this API.
                // See createUser method.
                List<String> groups = attr.getValue().stream().map(a -> a.toString()).collect(Collectors.toList());
                newUser.setGroups(groups);

            } else {
                if (!schema.isUserSchema(attr)) {
                    throw new InvalidAttributeValueException(String.format("Keycloak doesn't support to set '%s' attribute of User",
                            attr.getName()));
                }
                if (schema.isMultiValuedUserSchema(attr)) {
                    Map<String, List<String>> attrs = newUser.getAttributes();
                    if (attrs == null) {
                        attrs = new HashMap();
                    }
                    attrs.put(attr.getName(), attr.getValue().stream().map(a -> a.toString()).collect(Collectors.toList()));

                } else {
                    newUser.singleAttribute(attr.getName(), AttributeUtil.getStringValue(attr));
                }
            }
        }

        return newUser;
    }

    private void updatePassword(String realmName, String userId, CredentialRepresentation credential, final Boolean permanent)
            throws InvalidAttributeValueException {
        if (credential == null) {
            return;
        }

        try {
            users(realmName).get(userId).resetPassword(credential);

        } catch (BadRequestException e) {
            InvalidAttributeValueException ex = new InvalidAttributeValueException("Password policy error in keycloak", e);
            ex.setAffectedAttributeNames(Arrays.asList(OperationalAttributes.PASSWORD_NAME));
            throw ex;
        }
    }

    @Override
    public void updateUser(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications,
                           OperationOptions options) throws UnknownUidException {
        UsersResource usersResource = users(realmName);
        UserRepresentation current;
        List<String> addGroupIds = new ArrayList<>();
        List<String> removeGroupIds = new ArrayList<>();
        CredentialRepresentation credential = null;
        AttributeDelta realmRolesDelta = null;
        AttributeDelta clientRolesDelta = null;
        AttributeDelta federatedIdentitiesDelta = null;
        FederatedIdentityOps.Plan linkPlan = null;
        RoleDiff realmDiff = null;
        RoleDiff clientDiff = null;
        boolean userAttributeChanged = false;
        boolean disabled = false;

        try {
            UserResource user = usersResource.get(uid.getUidValue());
            current = user.toRepresentation();

            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(Uid.NAME)) {
                    // Keycloak doesn't support to modify 'id'
                    invalidSchema(delta.getName());

                } else if (delta.getName().equals(Name.NAME)) {
                    current.setUsername(AttributeDeltaUtil.getAsStringValue(delta));
                    userAttributeChanged = true;

                } else if (delta.getName().equals(ENABLE_NAME)) {
                    Boolean enabled = AttributeDeltaUtil.getBooleanValue(delta);
                    current.setEnabled(enabled);
                    disabled = Boolean.FALSE.equals(enabled);
                    userAttributeChanged = true;

                } else if (delta.getName().equals(OperationalAttributes.PASSWORD_NAME)) {
                    List<CredentialRepresentation> credentials = new ArrayList<>();
                    GuardedString password = AttributeDeltaUtil.getGuardedStringValue(delta);
                    password.access(a -> {
                        String clearPassword = String.valueOf(a);
                        CredentialRepresentation passwordRep = new CredentialRepresentation();
                        passwordRep.setType(CredentialRepresentation.PASSWORD);
                        passwordRep.setTemporary(Boolean.FALSE);
                        passwordRep.setValue(clearPassword);

                        credentials.add(passwordRep);
                    });
                    current.setCredentials(credentials);

                } else if (delta.getName().equals(ATTR_EMAIL)) {
                    current.setEmail(toKeycloakValue(schema.userSchema, delta));
                    userAttributeChanged = true;

                } else if (delta.getName().equals(ATTR_EMAIL_VERIFIED)) {
                    current.setEmailVerified(AttributeDeltaUtil.getBooleanValue(delta));
                    userAttributeChanged = true;

                } else if (delta.getName().equals(ATTR_FIRST_NAME)) {
                    current.setFirstName(toKeycloakValue(schema.userSchema, delta));
                    userAttributeChanged = true;

                } else if (delta.getName().equals(ATTR_LAST_NAME)) {
                    current.setLastName(toKeycloakValue(schema.userSchema, delta));
                    userAttributeChanged = true;

                } else if (delta.getName().equals(ATTR_REQUIRED_ACTIONS)) {
                    current.setRequiredActions(applyMultiValueDelta(current.getRequiredActions(), delta));
                    userAttributeChanged = true;

                } else if (delta.getName().equals(ATTR_GROUPS)) {
                    if (delta.getValuesToAdd() != null) {
                        for (Object group : delta.getValuesToAdd()) {
                            addGroupIds.add(group.toString());
                        }
                    }
                    if (delta.getValuesToRemove() != null) {
                        for (Object group : delta.getValuesToRemove()) {
                            removeGroupIds.add(group.toString());
                        }
                    }

                } else if (delta.getName().equals(ATTR_REALM_ROLES)) {
                    realmRolesDelta = delta;

                } else if (delta.getName().equals(ATTR_CLIENT_ROLES)) {
                    clientRolesDelta = delta;

                } else if (delta.getName().equals(ATTR_FEDERATED_IDENTITIES)) {
                    federatedIdentitiesDelta = delta;

                } else if (schema.isUserSchema(delta)) {
                    userAttributeChanged = true;
                    if (schema.isMultiValuedUserSchema(delta)) {
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

            // Always extract and clear credentials before the user update call.
            // KC 26 rejects credentials in the user update payload; passwords must be
            // set separately via the resetPassword API.
            List<CredentialRepresentation> credentials = current.getCredentials();
            if (credentials != null && credentials.size() == 1) {
                credential = credentials.get(0);
            }
            current.setCredentials(null);

            if (federatedIdentitiesDelta != null) {
                // Validate and plan before any write so a bad link fails the whole update.
                linkPlan = FederatedIdentityOps.plan(realm(realmName), FederatedIdentityOps.read(user),
                        federatedIdentitiesDelta);
                FederatedIdentityOps.requireNotHeldByOther(realm(realmName), linkPlan.add(), current.getId());
            }

            // Validate the role adds before the first write so a bad role does not leave a half-applied update.
            if (realmRolesDelta != null || clientRolesDelta != null) {
                Set<String> ignoredRoles = configuration.resolveIgnoredRoles();
                RoleMappingResource rm = user.roles();
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

            if (userAttributeChanged) {
                user.update(current);
            }

            // End sessions right after the disable is written, independent of the later sub-resource calls.
            if (disabled && configuration.isLogoutOnDisable()) {
                user.logout();
            }

        } catch (NotFoundException e) {
            LOGGER.warn("Not found user when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, USER_OBJECT_CLASS);
        }

        // We need to call another API to update password and add/remove group for this user.
        // It means that we can't execute this operation as a single transaction.
        // Therefore, Keycloak data may be inconsistent if below callings are failed.
        // Although this connector doesn't handle this situation, IDM can retry the update to resolve this inconsistency.

        updatePassword(realmName, current.getId(), credential, true);

        for (String groupId : addGroupIds) {
            try {
                users(realmName).get(current.getId()).joinGroup(groupId);
            } catch (NotFoundException e) {
                LOGGER.warn("The group is not found already. Skipping join the user. groupId: {0}, userId: {1}, username: {2}",
                        groupId, current.getId(), current.getUsername());
            }
        }
        for (String groupId : removeGroupIds) {
            try {
                users(realmName).get(current.getId()).leaveGroup(groupId);
            } catch (NotFoundException e) {
                LOGGER.warn("The group is not found already. Skipping join the user. groupId: {0}, userId: {1}, username: {2}",
                        groupId, current.getId(), current.getUsername());
            }
        }

        if (realmDiff != null || clientDiff != null) {
            RoleMappingResource rm = users(realmName).get(current.getId()).roles();
            RealmResource realm = realm(realmName);
            if (realmDiff != null) {
                RoleMappingOps.applyRealm(realm, rm, realmDiff);
            }
            if (clientDiff != null) {
                RoleMappingOps.applyClient(realm, rm, clientDiff);
            }
        }

        if (linkPlan != null && !linkPlan.isEmpty()) {
            FederatedIdentityOps.apply(users(realmName).get(current.getId()), linkPlan);
        }
    }

    private static List<String> applyMultiValueDelta(List<String> existing, AttributeDelta delta) {
        List<String> result;
        if (delta.getValuesToReplace() != null) {
            result = new ArrayList<>();
            for (Object v : delta.getValuesToReplace()) {
                if (v != null && !result.contains(v.toString())) result.add(v.toString());
            }
            return result;
        }
        result = existing == null ? new ArrayList<>() : new ArrayList<>(existing);
        if (delta.getValuesToRemove() != null) {
            for (Object v : delta.getValuesToRemove()) {
                if (v != null) result.remove(v.toString());
            }
        }
        if (delta.getValuesToAdd() != null) {
            for (Object v : delta.getValuesToAdd()) {
                if (v != null && !result.contains(v.toString())) result.add(v.toString());
            }
        }
        return result;
    }

    @Override
    public void deleteUser(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options)
            throws UnknownUidException {
        try {
            Response response = users(realmName).delete(uid.getUidValue());

            checkDeleteResult(response, "deleteUser");

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found user when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, USER_OBJECT_CLASS);
        }
    }

    @Override
    public void getUsers(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                         Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        UsersResource users = users(realmName);

        Integer count = users.count();

        int start = 0;
        int total = 0;

        while (total < count) {
            List<UserRepresentation> results = users.search("", start, queryPageSize, true);

            if (results.size() == 0) {
                break;
            }

            for (UserRepresentation rep : results) {
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
    public void getUser(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                        Set<String> attributesToGet, int queryPageSize) {
        try {
            UserRepresentation user = users(realmName).get(uid.getUidValue()).toRepresentation();

            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

            handler.handle(toConnectorObject(schema, realmName, user, attributesToGet, allowPartialAttributeValues, queryPageSize));

        } catch (NotFoundException e) {
            // Don't throw UnknownUidException
            // The executeQuery should not indicate any error in this case. It should not throw any exception.
            // MidPoint will see empty result set and it will figure out that there is no such object.
            LOGGER.warn("[{0}] Unknown userId: {1}, name: {2}", instanceName, uid.getUidValue(), uid.getNameHintValue());
            return;
        }
    }

    @Override
    public void getUser(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                        Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        UsersResource users = users(realmName);

        Integer count = users.count(name.getNameValue());

        int start = 0;
        int total = 0;

        while (total < count) {
            // KC's users.search(search, first, max, briefRepresentation) takes max=page size,
            // not an end index. Pass queryPageSize directly.
            List<UserRepresentation> results = users.search(name.getNameValue(), start, queryPageSize, true);

            if (results.size() == 0) {
                break;
            }

            for (UserRepresentation u : results) {
                if (u.getUsername().equalsIgnoreCase(name.getNameValue())) {
                    // Found
                    handler.handle(toConnectorObject(schema, realmName, u, attributesToGet, allowPartialAttributeValues, queryPageSize));
                    return;
                }
            }

            total += results.size();
            start += results.size();
        }

        // NotFound
        LOGGER.warn("[{0}] Unknown username: {1}", instanceName, name.getNameValue());
    }

    private ConnectorObject toConnectorObject(KeycloakSchema schema, String realmName, UserRepresentation user,
                                              Set<String> attributesToGet, boolean allowPartialAttributeValues, int queryPageSize) {
        final ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(USER_OBJECT_CLASS)
                // Always returns "id"
                .setUid(user.getId())
                // Always returns "username"
                .setName(user.getUsername());

        // Metadata
        if (shouldReturn(attributesToGet, ENABLE_NAME)) {
            builder.addAttribute(AttributeBuilder.buildEnabled(user.isEnabled()));
        }
        if (shouldReturn(attributesToGet, ATTR_CREATED_TIMESTAMP)) {
            builder.addAttribute(ATTR_CREATED_TIMESTAMP, KeycloakUtils.toZoneDateTime(user.getCreatedTimestamp()));
        }
        if (shouldReturn(attributesToGet, ATTR_EMAIL)) {
            builder.addAttribute(ATTR_EMAIL, user.getEmail());
        }
        if (shouldReturn(attributesToGet, ATTR_EMAIL_VERIFIED)) {
            builder.addAttribute(ATTR_EMAIL_VERIFIED, user.isEmailVerified());
        }
        if (shouldReturn(attributesToGet, ATTR_FIRST_NAME)) {
            builder.addAttribute(ATTR_FIRST_NAME, user.getFirstName());
        }
        if (shouldReturn(attributesToGet, ATTR_LAST_NAME)) {
            builder.addAttribute(ATTR_LAST_NAME, user.getLastName());
        }

        if (shouldReturn(attributesToGet, ATTR_REQUIRED_ACTIONS)) {
            List<String> actions = user.getRequiredActions();
            builder.addAttribute(ATTR_REQUIRED_ACTIONS, actions == null ? new ArrayList<String>() : actions);
        }

        Map<String, List<String>> attributes = user.getAttributes();
        if (attributes != null) {
            for (Map.Entry<String, List<String>> entry : user.getAttributes().entrySet()) {
                String a = entry.getKey();
                AttributeInfo attributeInfo = schema.getUserSchema(a);

                if (attributeInfo == null) {
                    LOGGER.ok("[{0}] Ignored. \"{1}\" is not defined in the user schema.", instanceName, a);
                    continue;
                }

                if (shouldReturn(attributesToGet, attributeInfo.getName())) {
                    builder.addAttribute(toConnectorAttribute(attributeInfo, entry));
                }
            }
        }

        if (allowPartialAttributeValues) {
            // Suppress fetching groups
            LOGGER.ok("[{0}] Suppress fetching groups because return partial attribute values is requested", instanceName);

            AttributeBuilder ab = new AttributeBuilder();
            ab.setName(ATTR_GROUPS).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab.addValue(Collections.EMPTY_LIST);
            builder.addAttribute(ab.build());
        } else {
            if (attributesToGet == null) {
                // Suppress fetching groups default
                LOGGER.ok("[{0}] Suppress fetching groups because returned by default is true", instanceName);

            } else if (shouldReturn(attributesToGet, ATTR_GROUPS)) {
                // Fetch groups
                LOGGER.ok("[{0}] Fetching groups because attributes to get is requested", instanceName);

                List<GroupRepresentation> groups = users(realmName).get(user.getId()).groups();
                builder.addAttribute(ATTR_GROUPS, groups.stream().map(g -> g.getId()).collect(Collectors.toList()));
            }
        }

        addRoleMappings(builder, realmName, user, attributesToGet, allowPartialAttributeValues);
        addFederatedIdentities(builder, realmName, user, attributesToGet, allowPartialAttributeValues);

        return builder.build();
    }

    private void addRoleMappings(ConnectorObjectBuilder builder, String realmName, UserRepresentation user,
                                 Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        for (String attrName : new String[]{ATTR_REALM_ROLES, ATTR_CLIENT_ROLES}) {
            if (allowPartialAttributeValues) {
                AttributeBuilder ab = new AttributeBuilder();
                ab.setName(attrName).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
                ab.addValue(Collections.EMPTY_LIST);
                builder.addAttribute(ab.build());

            } else if (attributesToGet != null && shouldReturn(attributesToGet, attrName)) {
                Set<String> ignoredRoles = configuration.resolveIgnoredRoles();
                RoleMappingResource rm = users(realmName).get(user.getId()).roles();
                Set<String> values = attrName.equals(ATTR_REALM_ROLES)
                        ? RoleMappingOps.readRealm(rm, ignoredRoles)
                        : RoleMappingOps.readClient(rm, ignoredRoles);
                builder.addAttribute(attrName, new ArrayList<>(values));
            }
        }
    }

    private void addFederatedIdentities(ConnectorObjectBuilder builder, String realmName, UserRepresentation user,
                                        Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        if (allowPartialAttributeValues) {
            AttributeBuilder ab = new AttributeBuilder();
            ab.setName(ATTR_FEDERATED_IDENTITIES).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab.addValue(Collections.EMPTY_LIST);
            builder.addAttribute(ab.build());

        } else if (attributesToGet != null && shouldReturn(attributesToGet, ATTR_FEDERATED_IDENTITIES)) {
            List<String> values = FederatedIdentityOps.read(users(realmName).get(user.getId())).stream()
                    .map(FederatedIdentityCodec::format).collect(Collectors.toList());
            builder.addAttribute(ATTR_FEDERATED_IDENTITIES, values);
        }
    }
}
