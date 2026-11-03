package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;

/**
 * Reference to a client role, encoded as {@code clientUuid/roleName}.
 */
public record ClientRoleRef(String clientUuid, String roleName) {

    public static ClientRoleRef parse(String value) {
        if (value == null) {
            throw new InvalidAttributeValueException("Client role reference must not be null");
        }
        int idx = value.indexOf('/');
        if (idx <= 0 || idx != value.lastIndexOf('/') || idx == value.length() - 1) {
            throw new InvalidAttributeValueException(
                    "Invalid client role reference '" + value + "', expected <clientUuid>/<roleName>");
        }
        return new ClientRoleRef(value.substring(0, idx), value.substring(idx + 1));
    }

    public String format() {
        return clientUuid + "/" + roleName;
    }
}
