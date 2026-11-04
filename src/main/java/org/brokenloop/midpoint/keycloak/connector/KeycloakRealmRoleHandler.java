/*
 *  Copyright Nomura Research Institute, Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.objects.*;

import java.util.Set;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUtils.createFullAttributesToGet;

/**
 * Handle keycloak realm role object.
 */
public class KeycloakRealmRoleHandler extends AbstractKeycloakHandler {

    public static final ObjectClass REALM_ROLE_OBJECT_CLASS = new ObjectClass("realmRole");

    private static final Log LOGGER = Log.getLog(KeycloakRealmRoleHandler.class);

    public static final String ATTR_NAME = "name";
    public static final String ATTR_REALM_ROLE_ID = "realmRoleId";
    public static final String ATTR_DESCRIPTION = "description";
    public static final String ATTR_ATTRIBUTES = "attributes";
    public static final String ATTR_COMPOSITE_REALM_ROLES = "compositeRealmRoles";
    public static final String ATTR_COMPOSITE_CLIENT_ROLES = "compositeClientRoles";

    public KeycloakRealmRoleHandler(String instanceName, KeycloakConfiguration configuration, KeycloakClient client,
                                    KeycloakSchema schema) {
        super(instanceName, configuration, client, schema);
    }

    public static ObjectClassInfo getSchema(String[] attributes) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(REALM_ROLE_OBJECT_CLASS.getObjectClassValue());

        builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                .setRequired(false)
                .setCreateable(false)
                .setUpdateable(false)
                .setNativeName(ATTR_REALM_ROLE_ID)
                .build());

        builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setUpdateable(true)
                .setNativeName(ATTR_NAME)
                .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                .build());

        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DESCRIPTION)
                .setRequired(false)
                .build());

        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ATTRIBUTES)
                .setRequired(false)
                .setMultiValued(true)
                .build());

        for (String compositeAttr : new String[]{ATTR_COMPOSITE_REALM_ROLES, ATTR_COMPOSITE_CLIENT_ROLES}) {
            builder.addAttributeInfo(AttributeInfoBuilder.define(compositeAttr)
                    .setMultiValued(true)
                    .setCreateable(true)
                    .setUpdateable(true)
                    .setReturnedByDefault(false)
                    .build());
        }

        ObjectClassInfo info = builder.build();

        LOGGER.info("The constructed realmRole core schema: {0}", info);

        return info;
    }

    @Override
    public Uid create(Set<Attribute> attributes) throws AlreadyExistsException {
        return client.realmRole().createRealmRole(schema, configuration.getTargetRealmName(), attributes);
    }

    @Override
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        client.realmRole().updateRealmRole(schema, configuration.getTargetRealmName(), uid, modifications, options);
        return null;
    }

    @Override
    public void delete(Uid uid, OperationOptions options) {
        client.realmRole().deleteRealmRole(schema, configuration.getTargetRealmName(), uid, options);
    }

    @Override
    public void query(KeycloakFilter filter, ResultsHandler resultsHandler, OperationOptions options) {
        Set<String> attributesToGet = createFullAttributesToGet(schema.realmRoleSchema, options);

        if (filter == null) {
            client.realmRole().getRealmRoles(schema, configuration.getTargetRealmName(),
                    resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
        } else {
            if (filter.isByUid()) {
                client.realmRole().getRealmRole(schema, configuration.getTargetRealmName(), filter.uid,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            } else {
                client.realmRole().getRealmRole(schema, configuration.getTargetRealmName(), filter.name,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            }
        }
    }
}
