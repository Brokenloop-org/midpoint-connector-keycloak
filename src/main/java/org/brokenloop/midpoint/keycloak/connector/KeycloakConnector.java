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

import org.brokenloop.midpoint.keycloak.connector.rest.KeycloakAdminRESTAdminClient;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.*;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.InstanceNameAware;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.operations.*;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import java.util.Set;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakClientHandler.CLIENT_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakClientRoleHandler.CLIENT_ROLE_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakGroupHandler.GROUP_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakOrganizationHandler.ORGANIZATION_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakRealmRoleHandler.REALM_ROLE_OBJECT_CLASS;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakUserHandler.USER_OBJECT_CLASS;

/**
 * Connector implementation for keycloak connector.
 *
 * @author Hiroyuki Wada
 */
@ConnectorClass(configurationClass = KeycloakConfiguration.class, displayNameKey = "NRI OpenStandia Keycloak Connector")
public class KeycloakConnector implements PoolableConnector, CreateOp, UpdateDeltaOp, DeleteOp, SchemaOp, TestOp, SearchOp<KeycloakFilter>, InstanceNameAware {

    private static final Log LOG = Log.getLog(KeycloakConnector.class);

    protected KeycloakConfiguration configuration;
    protected KeycloakClient client;

    /** Swapped atomically by schema(); operations read it once per call. */
    private volatile KeycloakSchema schema;
    private String instanceName;

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(Configuration configuration) {
        this.configuration = (KeycloakConfiguration) configuration;

        try {
            initClient();
            getSchema();
        } catch (RuntimeException e) {
            throw processRuntimeException(e);
        }

        LOG.ok("Connector {0} successfully initialized", getClass().getName());
    }

    protected void initClient() {
        if (configuration.isGrpcEnabled()) {
            // Not implemented yet
            client = null;

        } else {
            client = new KeycloakAdminRESTAdminClient(instanceName, configuration);
        }

    }

    @Override
    public Schema schema() {
        try {
            // Build completely first: a failed rebuild leaves the previous schema in place.
            KeycloakSchema rebuilt = new KeycloakSchema(configuration, client);
            schema = rebuilt;
            return rebuilt.schema;

        } catch (RuntimeException e) {
            throw processRuntimeException(e);
        }
    }

    private KeycloakSchema getSchema() {
        // Load schema map if it's not loaded yet
        KeycloakSchema current = schema;
        if (current == null) {
            schema();
            current = schema;
        }
        return current;
    }

    protected AbstractKeycloakHandler createKeycloakHandler(ObjectClass objectClass) {
        if (objectClass == null) {
            throw new InvalidAttributeValueException("ObjectClass value not provided");
        }

        // One snapshot per operation, so a concurrent schema() refresh cannot split a handler across two schemas.
        final KeycloakSchema schema = getSchema();

        if (objectClass.equals(USER_OBJECT_CLASS)) {
            return new KeycloakUserHandler(instanceName, configuration, client, schema);

        } else if (objectClass.equals(GROUP_OBJECT_CLASS)) {
            return new KeycloakGroupHandler(instanceName, configuration, client, schema);

        } else if (objectClass.equals(CLIENT_OBJECT_CLASS)) {
            return new KeycloakClientHandler(instanceName, configuration, client, schema);

        } else if (objectClass.equals(CLIENT_ROLE_OBJECT_CLASS)) {
            return new KeycloakClientRoleHandler(instanceName, configuration, client, schema);

        } else if (objectClass.equals(REALM_ROLE_OBJECT_CLASS)) {
            return new KeycloakRealmRoleHandler(instanceName, configuration, client, schema);

        } else if (objectClass.equals(ORGANIZATION_OBJECT_CLASS)) {
            if (!schema.organizationsAvailable) {
                LOG.error("Organization object class requested but unavailable on target realm '{0}'. "
                        + "Enable the 'organization' server feature and set organizationsEnabled=true on the realm.",
                        configuration.getTargetRealmName());
                throw new InvalidAttributeValueException(
                        "Organization object class is not available on the target Keycloak realm: "
                        + "enable the 'organization' server feature and set organizationsEnabled=true on the realm.");
            }
            return new KeycloakOrganizationHandler(instanceName, configuration, client, schema);

        } else {
            throw new InvalidAttributeValueException("Unsupported object class " + objectClass);
        }
    }

    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes, OperationOptions options) {
        if (createAttributes == null || createAttributes.isEmpty()) {
            throw new InvalidAttributeValueException("Attributes not provided or empty");
        }

        try {
            return createKeycloakHandler(objectClass).create(createAttributes);

        } catch (RuntimeException e) {
            throw processRuntimeException(e);
        }
    }

    @Override
    public Set<AttributeDelta> updateDelta(ObjectClass objectClass, Uid uid, Set<AttributeDelta> modifications, OperationOptions options) {
        if (uid == null) {
            throw new InvalidAttributeValueException("uid not provided");
        }
        if (modifications == null || modifications.isEmpty()) {
            throw new InvalidAttributeValueException("modifications not provided or empty");
        }

        try {
            return createKeycloakHandler(objectClass).updateDelta(uid, modifications, options);

        } catch (RuntimeException e) {
            throw processRuntimeException(e);
        }
    }

    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        if (uid == null) {
            throw new InvalidAttributeValueException("uid not provided");
        }

        try {
            createKeycloakHandler(objectClass).delete(uid, options);

        } catch (RuntimeException e) {
            throw processRuntimeException(e);
        }
    }

    @Override
    public FilterTranslator<KeycloakFilter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
        return new KeycloakFilterTranslator(objectClass, options);
    }

    @Override
    public void executeQuery(ObjectClass objectClass, KeycloakFilter filter, ResultsHandler resultsHandler, OperationOptions options) {
        try {
            createKeycloakHandler(objectClass).query(filter, resultsHandler, options);

        } catch (NotFoundException e) {
            // Don't throw UnknownUidException
            // The executeQuery should not indicate any error in this case. It should not throw any exception.
            // MidPoint will see empty result set and it will figure out that there is no such object.
            return;
        } catch (RuntimeException e) {
            throw processRuntimeException(e);
        }
    }

    @Override
    public void test() {
        try {
            dispose();
            initClient();
            client.test(configuration.getTargetRealmName());
            checkUserProfileReadable();
        } catch (RuntimeException e) {
            throw processRuntimeException(e);
        }
    }

    /** With the profile schema enabled, an unreadable User Profile must not pass as a healthy resource. */
    private void checkUserProfileReadable() {
        if (!configuration.isUserProfileSchemaEnabled()) {
            return;
        }
        String realmName = configuration.getTargetRealmName();
        try {
            client.getUserProfileConfig(realmName);
        } catch (RuntimeException e) {
            throw new ConnectorException(String.format(
                    "The user profile of realm '%s' could not be read although userProfileSchemaEnabled is true. "
                            + "The service account likely lacks a realm-management role: query-users (granted by "
                            + "view-users or manage-users) or view-realm is needed to read GET /admin/realms/%s/users/profile. "
                            + "Cause: %s", realmName, realmName, e.getMessage()), e);
        }
    }

    @Override
    public void dispose() {
        client.close();
        this.client = null;
    }

    @Override
    public void checkAlive() {
        // Do nothing
    }

    @Override
    public void setInstanceName(String instanceName) {
        // Called after initialized
        this.instanceName = instanceName;
    }

    protected ConnectorException processRuntimeException(RuntimeException e) {
        if (e instanceof ConnectorException) {
            return (ConnectorException) e;
        }
        if (e instanceof WebApplicationException) {
            return processKeycloakAdminRESTException((WebApplicationException) e);
        }
        // TODO handle gRPC exception
        return new ConnectorException(e);
    }

    private ConnectorException processKeycloakAdminRESTException(WebApplicationException e) {
        if (e instanceof BadRequestException) {
            return new InvalidAttributeValueException(e);
        }
        if (e instanceof NotFoundException) {
            return new UnknownUidException(e);
        }
        if (e instanceof ClientErrorException) {
            if (e.getResponse().getStatusInfo() == Response.Status.CONFLICT) {
                return new AlreadyExistsException(e);
            }
            if (e.getResponse().getStatusInfo() == Response.Status.TOO_MANY_REQUESTS) {
                return RetryableException.wrap(e.getMessage(), e);
            }
            throw new ConnectorIOException(e);
        }
        if (e instanceof InternalServerErrorException) {
            return RetryableException.wrap(e.getMessage(), e);
        }
        throw new ConnectorIOException(e);
    }
}
