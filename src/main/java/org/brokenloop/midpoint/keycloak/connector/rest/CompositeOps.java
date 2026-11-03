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
package org.brokenloop.midpoint.keycloak.connector.rest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.brokenloop.midpoint.keycloak.connector.ClientRoleRef;
import org.brokenloop.midpoint.keycloak.connector.KeycloakUtils;
import org.brokenloop.midpoint.keycloak.connector.RoleDiff;
import org.brokenloop.midpoint.keycloak.connector.RoleMappings;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeValueCompleteness;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.representations.idm.RoleRepresentation;

/**
 * Reads and applies the direct (first-level) composite children of realm roles and client roles.
 * The role ignore list does not apply to composites.
 */
public final class CompositeOps {

    private CompositeOps() {
    }

    /** Attribute names, shared by the realm role and client role object classes. */
    public static final String ATTR_COMPOSITE_REALM_ROLES = "compositeRealmRoles";
    public static final String ATTR_COMPOSITE_CLIENT_ROLES = "compositeClientRoles";

    /** Direct children of a role, split into realm roles (by name) and client roles ({@code clientUuid/roleName}). */
    public record Children(Set<String> realm, Set<String> client) {
    }

    /** Create-time attributes separated into the composite children and the remaining role attributes. */
    public record CreateSplit(Set<String> realm, Set<String> client, Set<Attribute> roleAttributes) {
    }

    /** Both kinds of direct children, from a single REST call (it returns realm and client children together). */
    public static Children read(RoleResource r) {
        Set<String> realm = new LinkedHashSet<>();
        Set<String> client = new LinkedHashSet<>();
        Set<RoleRepresentation> children = r.getRoleComposites();
        if (children != null) {
            for (RoleRepresentation c : children) {
                if (Boolean.TRUE.equals(c.getClientRole())) {
                    client.add(new ClientRoleRef(c.getContainerId(), c.getName()).format());
                } else {
                    realm.add(c.getName());
                }
            }
        }
        return new Children(realm, client);
    }

    /** Separates the composite attributes from the other attributes of a create request. */
    public static CreateSplit splitCreate(Set<Attribute> createAttributes) {
        Set<String> realm = new LinkedHashSet<>();
        Set<String> client = new LinkedHashSet<>();
        Set<Attribute> roleAttributes = new HashSet<>();
        for (Attribute attr : createAttributes) {
            if (attr.getName().equals(ATTR_COMPOSITE_REALM_ROLES)) {
                realm.addAll(valuesOf(attr));
            } else if (attr.getName().equals(ATTR_COMPOSITE_CLIENT_ROLES)) {
                client.addAll(valuesOf(attr));
            } else {
                roleAttributes.add(attr);
            }
        }
        return new CreateSplit(realm, client, roleAttributes);
    }

    /**
     * Adds the composite attributes to a role being read: INCOMPLETE (without values) when partial values are
     * allowed, otherwise the children when they were asked for. The role is read once.
     */
    public static void addToObject(ConnectorObjectBuilder builder, RoleResource role, Set<String> attributesToGet,
                                   boolean allowPartialAttributeValues) {
        Children children = null;
        for (String attrName : new String[]{ATTR_COMPOSITE_REALM_ROLES, ATTR_COMPOSITE_CLIENT_ROLES}) {
            if (allowPartialAttributeValues) {
                AttributeBuilder ab = new AttributeBuilder();
                ab.setName(attrName).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
                ab.addValue(Collections.EMPTY_LIST);
                builder.addAttribute(ab.build());

            } else if (attributesToGet != null && KeycloakUtils.shouldReturn(attributesToGet, attrName)) {
                if (children == null) {
                    children = read(role);
                }
                builder.addAttribute(attrName, new ArrayList<>(
                        attrName.equals(ATTR_COMPOSITE_REALM_ROLES) ? children.realm() : children.client()));
            }
        }
    }

    /** Diff of a composite delta against the current children. Nothing is ignored. */
    public static RoleDiff diff(Set<String> current, AttributeDelta delta) {
        return RoleMappings.diff(current, delta, Set.of());
    }

    /** Values of a create-time attribute, or an empty set. */
    public static Set<String> valuesOf(Attribute attr) {
        Set<String> values = new LinkedHashSet<>();
        if (attr.getValue() != null) {
            for (Object v : attr.getValue()) {
                if (v != null) {
                    values.add(v.toString());
                }
            }
        }
        return values;
    }

    /** Fails with InvalidAttributeValueException when a child to add does not exist. */
    public static void requireExisting(RealmResource realm, RoleDiff realmDiff, RoleDiff clientDiff) {
        RoleMappingOps.requireExisting(realm, realmDiff.toAdd(), clientDiff.toAdd());
    }

    public static void apply(RealmResource realm, RoleResource r, RoleDiff realmDiff, RoleDiff clientDiff) {
        List<RoleRepresentation> add = new ArrayList<>();
        List<RoleRepresentation> remove = new ArrayList<>();

        for (String name : realmDiff.toAdd()) {
            add.add(requireRealm(realm, name));
        }
        for (String name : realmDiff.toRemove()) {
            RoleRepresentation role = RoleMappingOps.resolveRealmRole(realm, name);
            if (role != null) {
                remove.add(role);
            }
        }
        for (List<RoleRepresentation> roles : RoleMappingOps.resolveClient(realm, clientDiff.toAdd(), true).values()) {
            add.addAll(roles);
        }
        for (List<RoleRepresentation> roles : RoleMappingOps.resolveClient(realm, clientDiff.toRemove(), false).values()) {
            remove.addAll(roles);
        }

        if (!add.isEmpty()) {
            r.addComposites(add);
        }
        if (!remove.isEmpty()) {
            r.deleteComposites(remove);
        }
    }

    private static RoleRepresentation requireRealm(RealmResource realm, String name) {
        RoleRepresentation role = RoleMappingOps.resolveRealmRole(realm, name);
        if (role == null) {
            throw new InvalidAttributeValueException(
                    "Unknown realm role '" + name + "'");
        }
        return role;
    }
}
