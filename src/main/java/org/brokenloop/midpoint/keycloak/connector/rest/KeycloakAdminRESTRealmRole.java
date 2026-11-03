/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package org.brokenloop.midpoint.keycloak.connector.rest;

import jakarta.ws.rs.NotFoundException;
import org.brokenloop.midpoint.keycloak.connector.KeycloakClient;
import org.brokenloop.midpoint.keycloak.connector.KeycloakConfiguration;
import org.brokenloop.midpoint.keycloak.connector.KeycloakSchema;
import org.brokenloop.midpoint.keycloak.connector.RoleDiff;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.*;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakRealmRoleHandler.*;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakUtils.*;

/**
 * Keycloak realm role implementation which uses Keycloak Admin REST client.
 */
public class KeycloakAdminRESTRealmRole implements KeycloakClient.RealmRole {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTRealmRole.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private final Keycloak adminClient;

    public KeycloakAdminRESTRealmRole(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private RolesResource roles(String realmName) {
        return realm(realmName).roles();
    }

    @Override
    public Uid createRealmRole(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException {
        Set<String> compositeRealm = new LinkedHashSet<>();
        Set<String> compositeClient = new LinkedHashSet<>();
        Set<Attribute> roleAttributes = new HashSet<>();
        for (Attribute attr : createAttributes) {
            if (attr.getName().equals(ATTR_COMPOSITE_REALM_ROLES)) {
                compositeRealm.addAll(CompositeOps.valuesOf(attr));
            } else if (attr.getName().equals(ATTR_COMPOSITE_CLIENT_ROLES)) {
                compositeClient.addAll(CompositeOps.valuesOf(attr));
            } else {
                roleAttributes.add(attr);
            }
        }

        RoleRepresentation rep = toRealmRoleRep(roleAttributes);

        if (rep.getName() == null) {
            throw new InvalidAttributeValueException("Must define name for the realmRole object");
        }

        // Validate the children up-front so an unknown child does not leave a half-created role behind.
        RoleMappingOps.requireExisting(realm(realmName), compositeRealm, compositeClient);

        roles(realmName).create(rep);

        // Fetch back to get the generated id
        RoleRepresentation created = roles(realmName).get(rep.getName()).toRepresentation();

        // KC may not accept attributes in the create call; if so, update them now
        if (rep.getAttributes() != null && !rep.getAttributes().isEmpty()
                && (created.getAttributes() == null || created.getAttributes().isEmpty())) {
            created.setAttributes(rep.getAttributes());
            realm(realmName).rolesById().updateRole(created.getId(), created);
        }

        if (!compositeRealm.isEmpty() || !compositeClient.isEmpty()) {
            CompositeOps.apply(realm(realmName), roles(realmName).get(created.getName()),
                    new RoleDiff(compositeRealm, Set.of()), new RoleDiff(compositeClient, Set.of()));
        }

        return new Uid(created.getId(), new Name(created.getName()));
    }

    protected RoleRepresentation toRealmRoleRep(Set<Attribute> attributes) {
        RoleRepresentation newRole = new RoleRepresentation();
        newRole.setClientRole(false);

        for (Attribute attr : attributes) {
            // Uid is server-generated; not stored on the rep.
            if (attr.getName().equals(Uid.NAME)) {
                continue;
            }

            if (attr.getName().equals(Name.NAME)) {
                newRole.setName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ATTR_DESCRIPTION)) {
                newRole.setDescription(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_ATTRIBUTES)) {
                Map<String, List<String>> attrs = newRole.getAttributes();
                if (attrs == null) {
                    attrs = new HashMap<>();
                }

                for (Object v : attr.getValue()) {
                    Map.Entry<String, List<String>> e = parseKeyValueAttribute(v.toString());
                    attrs.put(e.getKey(), e.getValue());
                }

                newRole.setAttributes(attrs);

            } else {
                invalidSchema(attr.getName());
            }
        }

        return newRole;
    }

    @Override
    public void updateRealmRole(KeycloakSchema schema, String realmName, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        try {
            RoleRepresentation current = realm(realmName).rolesById().getRole(uid.getUidValue());
            AttributeDelta compositeRealmDelta = null;
            AttributeDelta compositeClientDelta = null;

            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(ATTR_COMPOSITE_REALM_ROLES)) {
                    compositeRealmDelta = delta;

                } else if (delta.getName().equals(ATTR_COMPOSITE_CLIENT_ROLES)) {
                    compositeClientDelta = delta;

                } else if (delta.getName().equals(Name.NAME)) {
                    current.setName(AttributeDeltaUtil.getAsStringValue(delta));

                } else if (delta.getName().equals(ATTR_DESCRIPTION)) {
                    current.setDescription(AttributeDeltaUtil.getStringValue(delta));

                } else if (delta.getName().equals(ATTR_ATTRIBUTES)) {
                    Map<String, List<String>> attrs = current.getAttributes();
                    if (attrs == null) {
                        attrs = new HashMap<>();
                    }

                    if (delta.getValuesToRemove() != null) {
                        for (Object v : delta.getValuesToRemove()) {
                            attrs.remove(parseKeyValueKey(v.toString()));
                        }
                    }
                    if (delta.getValuesToAdd() != null) {
                        for (Object v : delta.getValuesToAdd()) {
                            Map.Entry<String, List<String>> e = parseKeyValueAttribute(v.toString());
                            attrs.put(e.getKey(), e.getValue());
                        }
                    }

                    current.setAttributes(attrs);

                } else {
                    invalidSchema(delta.getName());
                }
            }

            RoleDiff realmDiff = new RoleDiff(Set.of(), Set.of());
            RoleDiff clientDiff = new RoleDiff(Set.of(), Set.of());
            if (compositeRealmDelta != null || compositeClientDelta != null) {
                RoleResource existing = roles(realmName).get(
                        realm(realmName).rolesById().getRole(uid.getUidValue()).getName());
                if (compositeRealmDelta != null) {
                    realmDiff = CompositeOps.diff(CompositeOps.readRealm(existing), compositeRealmDelta);
                }
                if (compositeClientDelta != null) {
                    clientDiff = CompositeOps.diff(CompositeOps.readClient(realm(realmName), existing),
                            compositeClientDelta);
                }
                CompositeOps.requireExisting(realm(realmName), realmDiff, clientDiff);
            }

            realm(realmName).rolesById().updateRole(current.getId(), current);

            // The role may have been renamed, so look it up again by its (new) name.
            if (compositeRealmDelta != null || compositeClientDelta != null) {
                CompositeOps.apply(realm(realmName), roles(realmName).get(current.getName()), realmDiff, clientDiff);
            }

        } catch (NotFoundException e) {
            LOGGER.warn("Not found realmRole when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, REALM_ROLE_OBJECT_CLASS);
        }
    }

    @Override
    public void deleteRealmRole(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException {
        try {
            realm(realmName).rolesById().deleteRole(uid.getUidValue());

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found realmRole when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, REALM_ROLE_OBJECT_CLASS);
        }
    }

    @Override
    public void getRealmRoles(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                              Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);

        // RolesResource.list() returns all realm roles
        List<RoleRepresentation> roles = roles(realmName).list();

        for (RoleRepresentation rep : roles) {
            if (!handler.handle(toConnectorObject(realmName, rep, attributesToGet, allowPartialAttributeValues))) {
                KeycloakRESTUtils.signalAllResultsReturned(handler);
                return;
            }
        }

        KeycloakRESTUtils.signalAllResultsReturned(handler);
    }


    @Override
    public void getRealmRole(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                             Set<String> attributesToGet, int queryPageSize) {
        try {
            RoleRepresentation rep = realm(realmName).rolesById().getRole(uid.getUidValue());
            if (rep == null) {
                LOGGER.warn("[{0}] Unknown realmRole uuid: {1}", instanceName, uid.getUidValue());
                return;
            }
            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);
            handler.handle(toConnectorObject(realmName, rep, attributesToGet, allowPartialAttributeValues));

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Unknown realmRole uuid: {1}", instanceName, uid.getUidValue());
        }
    }

    @Override
    public void getRealmRole(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                             Set<String> attributesToGet, int queryPageSize) {
        try {
            RoleRepresentation rep = roles(realmName).get(name.getNameValue()).toRepresentation();
            if (rep == null) {
                LOGGER.warn("[{0}] Unknown realmRole name: {1}", instanceName, name.getNameValue());
                return;
            }
            boolean allowPartialAttributeValues = shouldAllowPartialAttributeValues(options);
            handler.handle(toConnectorObject(realmName, rep, attributesToGet, allowPartialAttributeValues));

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Unknown realmRole name: {1}", instanceName, name.getNameValue());
        }
    }

    private ConnectorObject toConnectorObject(String realmName, RoleRepresentation rep, Set<String> attributesToGet,
                                              boolean allowPartialAttributeValues) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(REALM_ROLE_OBJECT_CLASS)
                .setUid(rep.getId())
                .setName(rep.getName());

        if (shouldReturn(attributesToGet, ATTR_DESCRIPTION)) {
            builder.addAttribute(ATTR_DESCRIPTION, rep.getDescription());
        }

        if (shouldReturn(attributesToGet, ATTR_ATTRIBUTES)) {
            Map<String, List<String>> attributes = rep.getAttributes();
            List<String> genericAttributes = new ArrayList<>();
            if (attributes != null) {
                for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
                    genericAttributes.add(String.format("%s=%s", entry.getKey(),
                            String.join("##", entry.getValue())));
                }
            }
            builder.addAttribute(ATTR_ATTRIBUTES, genericAttributes);
        }

        addComposites(builder, realmName, rep, attributesToGet, allowPartialAttributeValues);

        return builder.build();
    }

    private void addComposites(ConnectorObjectBuilder builder, String realmName, RoleRepresentation rep,
                               Set<String> attributesToGet, boolean allowPartialAttributeValues) {
        for (String attrName : new String[]{ATTR_COMPOSITE_REALM_ROLES, ATTR_COMPOSITE_CLIENT_ROLES}) {
            if (allowPartialAttributeValues) {
                AttributeBuilder ab = new AttributeBuilder();
                ab.setName(attrName).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
                ab.addValue(Collections.EMPTY_LIST);
                builder.addAttribute(ab.build());

            } else if (attributesToGet != null && shouldReturn(attributesToGet, attrName)) {
                RoleResource resource = roles(realmName).get(rep.getName());
                Set<String> values = attrName.equals(ATTR_COMPOSITE_REALM_ROLES)
                        ? CompositeOps.readRealm(resource)
                        : CompositeOps.readClient(realm(realmName), resource);
                builder.addAttribute(attrName, new ArrayList<>(values));
            }
        }
    }
}
