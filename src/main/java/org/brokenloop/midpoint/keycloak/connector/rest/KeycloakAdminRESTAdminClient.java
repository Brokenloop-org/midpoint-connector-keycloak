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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.brokenloop.midpoint.keycloak.connector.KeycloakClient;
import org.brokenloop.midpoint.keycloak.connector.KeycloakConfiguration;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.info.ServerInfoRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;

import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.ext.ContextResolver;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakUtils.getRootCause;

/**
 * Keycloak client implementation which uses Keycloak Admin REST client.
 *
 * @author Hiroyuki Wada
 */
public class KeycloakAdminRESTAdminClient implements KeycloakClient {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTAdminClient.class);

    private static final ContextResolver<ObjectMapper> LENIENT_MAPPER_RESOLVER = new ContextResolver<>() {
        private final ObjectMapper mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        @Override
        public ObjectMapper getContext(Class<?> type) {
            return mapper;
        }
    };

    private final String instanceName;
    private final KeycloakAdminRESTUser user;
    private final KeycloakAdminRESTGroup group;
    private final KeycloakAdminRESTClient client;
    private final KeycloakAdminRESTClientRole clientRole;
    private final KeycloakAdminRESTRealmRole realmRole;
    private final KeycloakAdminRESTOrganization organization;
    private Keycloak adminClient;

    public KeycloakAdminRESTAdminClient(String instanceName, KeycloakConfiguration configuration) {
        this.instanceName = instanceName;

        ResteasyClientBuilder resteasyClientBuilder = new ResteasyClientBuilderImpl();
        resteasyClientBuilder.connectionPoolSize(20);
        // Tolerate fields that newer servers add to representations unknown to this client version.
        resteasyClientBuilder.register(LENIENT_MAPPER_RESOLVER);

        // HTTP proxy configuration
        if (configuration.getHttpProxyHost() != null && configuration.getHttpProxyPort() != 0) {
            final String httpProxyHost = configuration.getHttpProxyHost();
            final String httpProxyScheme = configuration.getHttpProxyScheme();

            if (StringUtil.isNotBlank(configuration.getHttpProxyUser()) && configuration.getHttpProxyPassword() != null) {
                // Note: RESTEasy / Apache HttpClient does not parse userinfo out of the
                // proxy host string for authentication. Embedding "user:pass@host" here
                // is a best-effort interpolation; URL-encode the credentials so any
                // special characters (e.g. ':' '@' '#' '?') don't corrupt the host
                // string. For reliable authenticated proxy support, configure proxy
                // auth at the JVM level instead.
                configuration.getHttpProxyPassword().access(s -> {
                    String encodedUser = URLEncoder.encode(
                            configuration.getHttpProxyUser(), StandardCharsets.UTF_8);
                    String encodedPass = URLEncoder.encode(
                            String.valueOf(s), StandardCharsets.UTF_8);
                    String httpProxyHostWithAuth = String.format("%s:%s@%s",
                            encodedUser, encodedPass, httpProxyHost);
                    resteasyClientBuilder.defaultProxy(httpProxyHostWithAuth,
                            configuration.getHttpProxyPort(), httpProxyScheme);
                });
            } else {
                resteasyClientBuilder.defaultProxy(httpProxyHost,
                        configuration.getHttpProxyPort(), httpProxyScheme);
            }
        }

        // grant_type=password mode
        if (configuration.getUsername() != null && configuration.getPassword() != null) {
            configuration.getPassword().access(s -> {
                adminClient = KeycloakBuilder.builder()
                        .serverUrl(configuration.getServerUrl())
                        .realm(configuration.getRealmName())
                        .grantType("password")
                        .username(configuration.getUsername())
                        .password(String.valueOf(s))
                        .clientId(configuration.getClientId())
                        .resteasyClient(resteasyClientBuilder.build())
                        .build();
            });
        } else if (configuration.getClientSecret() != null) {
            configuration.getClientSecret().access(s -> {
                adminClient = KeycloakBuilder.builder()
                        .serverUrl(configuration.getServerUrl())
                        .realm(configuration.getRealmName())
                        .grantType("client_credentials")
                        .clientId(configuration.getClientId())
                        .clientSecret(String.valueOf(s))
                        .resteasyClient(resteasyClientBuilder.build())
                        .build();
            });
        }

        this.user = new KeycloakAdminRESTUser(instanceName, configuration, adminClient);
        this.group = new KeycloakAdminRESTGroup(instanceName, configuration, adminClient);
        this.client = new KeycloakAdminRESTClient(instanceName, configuration, adminClient);
        this.clientRole = new KeycloakAdminRESTClientRole(instanceName, configuration, adminClient);
        this.realmRole = new KeycloakAdminRESTRealmRole(instanceName, configuration, adminClient);
        this.organization = new KeycloakAdminRESTOrganization(instanceName, configuration, adminClient);
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    @Override
    public void test(String realmName) {
        try {
            Boolean enabled = adminClient.realm(realmName).toRepresentation().isEnabled();
            if (!Boolean.TRUE.equals(enabled)) {
                throw new ConnectorException("The keycloak realm isn't active.");
            }
        } catch (ProcessingException e) {
            // Keycloak admin-client might throw exception due to version mismatch...

            Throwable rootCause = getRootCause(e);
            if (rootCause instanceof UnrecognizedPropertyException) {
                return;
            }
            throw new ConnectorException("Failed to test the Keycloak connector.", e);
        }
    }

    @Override
    public String getVersion() {
        ServerInfoRepresentation info = adminClient.serverInfo().getInfo();
        return info.getSystemInfo().getVersion();
    }

    @Override
    public boolean isFeatureEnabled(String featureName) {
        ServerInfoRepresentation info = adminClient.serverInfo().getInfo();
        if (info.getFeatures() == null) {
            return false;
        }
        return info.getFeatures().stream()
                .anyMatch(f -> featureName.equalsIgnoreCase(f.getName()) && f.isEnabled());
    }

    @Override
    public UPConfig getUserProfileConfig(String realmName) {
        return realm(realmName).users().userProfile().getConfiguration();
    }

    @Override
    public boolean isRealmOrganizationsEnabled(String realmName) {
        try {
            Boolean enabled = adminClient.realm(realmName).toRepresentation().isOrganizationsEnabled();
            return Boolean.TRUE.equals(enabled);
        } catch (Exception e) {
            LOGGER.warn("[{0}] Failed to check organizationsEnabled for realm {1}: {2}",
                    instanceName, realmName, e.getMessage());
            return false;
        }
    }

    @Override
    public User user() {
        return user;
    }

    @Override
    public Group group() {
        return group;
    }

    @Override
    public Client client() {
        return client;
    }

    @Override
    public ClientRole clientRole() {
        return clientRole;
    }

    @Override
    public RealmRole realmRole() {
        return realmRole;
    }

    @Override
    public Organization organization() {
        return organization;
    }

    @Override
    public void close() {
        adminClient.close();
    }
}
