package org.brokenloop.midpoint.keycloak.connector.rest;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.brokenloop.midpoint.keycloak.connector.ClientRoleRef;
import org.brokenloop.midpoint.keycloak.connector.RoleDiff;
import org.brokenloop.midpoint.keycloak.connector.RoleMappings;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import jakarta.ws.rs.NotFoundException;

/**
 * Reads and applies direct realm-role and client-role mappings on any Keycloak role-mapping holder
 * (users, groups).
 */
public final class RoleMappingOps {

    private static final Log LOGGER = Log.getLog(RoleMappingOps.class);

    private RoleMappingOps() {
    }

    /** Direct realm role names, without the ignored ones. */
    public static Set<String> readRealm(RoleMappingResource rm, Set<String> ignored) {
        List<String> names = new ArrayList<>();
        List<RoleRepresentation> roles = rm.realmLevel().listAll();
        if (roles != null) {
            for (RoleRepresentation r : roles) {
                names.add(r.getName());
            }
        }
        return RoleMappings.withoutIgnored(names, ignored);
    }

    /** Direct client roles formatted as {@code clientUuid/roleName}, without the ignored ones. */
    public static Set<String> readClient(RoleMappingResource rm, Set<String> ignored) {
        List<String> refs = new ArrayList<>();
        MappingsRepresentation all = rm.getAll();
        Map<String, ClientMappingsRepresentation> clients = all == null ? null : all.getClientMappings();
        if (clients != null) {
            for (ClientMappingsRepresentation c : clients.values()) {
                if (c.getMappings() == null) {
                    continue;
                }
                for (RoleRepresentation r : c.getMappings()) {
                    refs.add(new ClientRoleRef(c.getId(), r.getName()).format());
                }
            }
        }
        return RoleMappings.withoutIgnored(refs, ignored);
    }

    public static void applyRealm(RealmResource realm, RoleMappingResource rm, RoleDiff diff) {
        List<RoleRepresentation> add = new ArrayList<>();
        for (String name : diff.toAdd()) {
            RoleRepresentation role = resolveRealmRole(realm, name);
            if (role == null) {
                throw new InvalidAttributeValueException("Unknown realm role '" + name + "'");
            }
            add.add(role);
        }
        List<RoleRepresentation> remove = new ArrayList<>();
        for (String name : diff.toRemove()) {
            RoleRepresentation role = resolveRealmRole(realm, name);
            if (role == null) {
                LOGGER.warn("Realm role '{0}' not found. Skipping its removal.", name);
                continue;
            }
            remove.add(role);
        }
        if (!add.isEmpty()) {
            rm.realmLevel().add(add);
        }
        if (!remove.isEmpty()) {
            rm.realmLevel().remove(remove);
        }
    }

    public static void applyClient(RealmResource realm, RoleMappingResource rm, RoleDiff diff) {
        Map<String, List<RoleRepresentation>> add = resolveClient(realm, diff.toAdd(), true);
        Map<String, List<RoleRepresentation>> remove = resolveClient(realm, diff.toRemove(), false);
        for (Map.Entry<String, List<RoleRepresentation>> e : add.entrySet()) {
            rm.clientLevel(e.getKey()).add(e.getValue());
        }
        for (Map.Entry<String, List<RoleRepresentation>> e : remove.entrySet()) {
            rm.clientLevel(e.getKey()).remove(e.getValue());
        }
    }

    private static RoleRepresentation resolveRealmRole(RealmResource realm, String name) {
        try {
            return realm.roles().get(name).toRepresentation();
        } catch (NotFoundException e) {
            return null;
        }
    }

    /**
     * Resolves references grouped by client UUID. Unknown values fail when {@code strict}, else are skipped.
     */
    private static Map<String, List<RoleRepresentation>> resolveClient(RealmResource realm, Set<String> refs,
                                                                       boolean strict) {
        Map<String, List<RoleRepresentation>> byClient = new LinkedHashMap<>();
        for (String value : new LinkedHashSet<>(refs)) {
            ClientRoleRef ref = ClientRoleRef.parse(value);
            RoleRepresentation role;
            try {
                role = realm.clients().get(ref.clientUuid()).roles().get(ref.roleName()).toRepresentation();
            } catch (NotFoundException e) {
                if (strict) {
                    throw new InvalidAttributeValueException("Unknown client role '" + value + "'");
                }
                LOGGER.warn("Client role '{0}' not found. Skipping its removal.", value);
                continue;
            }
            byClient.computeIfAbsent(ref.clientUuid(), k -> new ArrayList<>()).add(role);
        }
        return byClient;
    }
}
