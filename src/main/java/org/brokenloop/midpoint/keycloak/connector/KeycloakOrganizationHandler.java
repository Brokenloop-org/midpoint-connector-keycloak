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
 * Handle Keycloak Organization object (KC 26+).
 * Requires the "organization" feature flag to be enabled on the Keycloak server.
 */
public class KeycloakOrganizationHandler extends AbstractKeycloakHandler {

    public static final ObjectClass ORGANIZATION_OBJECT_CLASS = new ObjectClass("organization");

    private static final Log LOGGER = Log.getLog(KeycloakOrganizationHandler.class);

    public static final String ATTR_NAME = "name";
    public static final String ATTR_ORGANIZATION_ID = "organizationId";
    public static final String ATTR_ALIAS = "alias";
    public static final String ATTR_DESCRIPTION = "description";
    public static final String ATTR_REDIRECT_URL = "redirectUrl";
    public static final String ATTR_DOMAINS = "domains";
    public static final String ATTR_MEMBERS = "members";
    public static final String ATTR_ATTRIBUTES = "attributes";

    public KeycloakOrganizationHandler(String instanceName, KeycloakConfiguration configuration, KeycloakClient client,
                                       KeycloakSchema schema) {
        super(instanceName, configuration, client, schema);
    }

    public static ObjectClassInfo getSchema(String[] attributes) {
        ObjectClassInfoBuilder builder = new ObjectClassInfoBuilder();
        builder.setType(ORGANIZATION_OBJECT_CLASS.getObjectClassValue());

        builder.addAttributeInfo(AttributeInfoBuilder.define(Uid.NAME)
                .setRequired(false)
                .setCreateable(false)
                .setUpdateable(false)
                .setNativeName(ATTR_ORGANIZATION_ID)
                .build());

        builder.addAttributeInfo(AttributeInfoBuilder.define(Name.NAME)
                .setRequired(true)
                .setUpdateable(true)
                .setNativeName(ATTR_NAME)
                .setSubtype(AttributeInfo.Subtypes.STRING_CASE_IGNORE)
                .build());

        builder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ALIAS)
                .setRequired(false)
                .build());

        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DESCRIPTION)
                .setRequired(false)
                .build());

        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_REDIRECT_URL)
                .setRequired(false)
                .build());

        // Domains: multi-valued, format "name:verified" (e.g. "example.com:true")
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DOMAINS)
                .setRequired(false)
                .setMultiValued(true)
                .build());

        // Members: multi-valued list of user IDs (not returned by default - needs explicit fetch)
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_MEMBERS)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());

        // Attributes: multi-valued, key=value format
        builder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_ATTRIBUTES)
                .setRequired(false)
                .setMultiValued(true)
                .build());

        ObjectClassInfo info = builder.build();

        LOGGER.info("The constructed organization core schema: {0}", info);

        return info;
    }

    @Override
    public Uid create(Set<Attribute> attributes) throws AlreadyExistsException {
        return client.organization().createOrganization(schema, configuration.getTargetRealmName(), attributes);
    }

    @Override
    public Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        client.organization().updateOrganization(schema, configuration.getTargetRealmName(), uid, modifications, options);
        return null;
    }

    @Override
    public void delete(Uid uid, OperationOptions options) {
        client.organization().deleteOrganization(schema, configuration.getTargetRealmName(), uid, options);
    }

    @Override
    public void query(KeycloakFilter filter, ResultsHandler resultsHandler, OperationOptions options) {
        Set<String> attributesToGet = createFullAttributesToGet(schema.organizationSchema, options);

        if (filter == null) {
            client.organization().getOrganizations(schema, configuration.getTargetRealmName(),
                    resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
        } else {
            if (filter.isByUid()) {
                client.organization().getOrganization(schema, configuration.getTargetRealmName(), filter.uid,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            } else {
                client.organization().getOrganization(schema, configuration.getTargetRealmName(), filter.name,
                        resultsHandler, options, attributesToGet, configuration.getQueryPageSize());
            }
        }
    }
}
