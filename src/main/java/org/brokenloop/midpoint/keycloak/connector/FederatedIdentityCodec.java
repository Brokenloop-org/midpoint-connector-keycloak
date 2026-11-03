/*
 *  Copyright the midpoint-connector-keycloak contributors
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Converts federated identity links to and from their JSON attribute value:
 * {@code {"identityProvider":"..","userId":"..","userName":".."}}.
 */
public final class FederatedIdentityCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private FederatedIdentityCodec() {
    }

    /** Parses a link; {@code identityProvider} and {@code userId} are required, {@code userName} defaults to the user id. */
    public static FederatedIdentityRepresentation parse(String json) {
        if (json == null) {
            throw new InvalidAttributeValueException("Federated identity value must not be null");
        }
        JsonNode node;
        try {
            node = MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new InvalidAttributeValueException("Invalid federated identity '" + json + "', expected JSON", e);
        }
        if (node == null || !node.isObject()) {
            throw new InvalidAttributeValueException("Invalid federated identity '" + json + "', expected a JSON object");
        }
        String identityProvider = text(node, "identityProvider");
        String userId = text(node, "userId");
        if (identityProvider == null || identityProvider.isEmpty() || userId == null || userId.isEmpty()) {
            throw new InvalidAttributeValueException(
                    "Invalid federated identity '" + json + "', 'identityProvider' and 'userId' are required");
        }
        String userName = text(node, "userName");
        FederatedIdentityRepresentation rep = new FederatedIdentityRepresentation();
        rep.setIdentityProvider(identityProvider);
        rep.setUserId(userId);
        rep.setUserName(userName == null || userName.isEmpty() ? userId : userName);
        return rep;
    }

    /** Canonical JSON with fixed key order and no whitespace. */
    public static String format(FederatedIdentityRepresentation rep) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("identityProvider", rep.getIdentityProvider());
        fields.put("userId", rep.getUserId());
        fields.put("userName", rep.getUserName());
        try {
            return MAPPER.writeValueAsString(fields);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && v.isTextual() ? v.asText() : null;
    }
}
