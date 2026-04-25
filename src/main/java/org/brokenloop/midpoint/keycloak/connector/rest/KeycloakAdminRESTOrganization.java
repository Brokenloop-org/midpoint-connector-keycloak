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
import jakarta.ws.rs.core.Response;
import org.brokenloop.midpoint.keycloak.connector.KeycloakClient;
import org.brokenloop.midpoint.keycloak.connector.KeycloakConfiguration;
import org.brokenloop.midpoint.keycloak.connector.KeycloakSchema;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.admin.client.resource.OrganizationsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.MemberRepresentation;
import org.keycloak.representations.idm.OrganizationDomainRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;

import java.util.*;
import java.util.stream.Collectors;

import static org.brokenloop.midpoint.keycloak.connector.KeycloakOrganizationHandler.*;
import static org.brokenloop.midpoint.keycloak.connector.KeycloakUtils.*;
import static org.brokenloop.midpoint.keycloak.connector.rest.KeycloakRESTUtils.checkCreateResult;
import static org.identityconnectors.framework.common.objects.OperationalAttributes.ENABLE_NAME;

/**
 * Keycloak Organization implementation (KC 26+).
 * Requires the "organization" feature flag to be enabled on the Keycloak server.
 */
public class KeycloakAdminRESTOrganization implements KeycloakClient.Organization {

    private static final Log LOGGER = Log.getLog(KeycloakAdminRESTOrganization.class);

    private final String instanceName;
    private final KeycloakConfiguration configuration;
    private final Keycloak adminClient;

    public KeycloakAdminRESTOrganization(String instanceName, KeycloakConfiguration configuration, Keycloak adminClient) {
        this.instanceName = instanceName;
        this.configuration = configuration;
        this.adminClient = adminClient;
    }

    private RealmResource realm(String realmName) {
        return adminClient.realm(realmName);
    }

    private OrganizationsResource organizations(String realmName) {
        return realm(realmName).organizations();
    }

    @Override
    public Uid createOrganization(KeycloakSchema schema, String realmName, Set<Attribute> createAttributes) throws AlreadyExistsException {
        OrganizationRepresentation rep = toOrganizationRep(createAttributes);

        if (rep.getName() == null) {
            throw new InvalidAttributeValueException("Must define name for the organization object");
        }

        Response res = organizations(realmName).create(rep);
        String uuid = checkCreateResult(res, "createOrganization");

        return new Uid(uuid, new Name(rep.getName()));
    }

    protected OrganizationRepresentation toOrganizationRep(Set<Attribute> attributes) {
        OrganizationRepresentation org = new OrganizationRepresentation();
        org.setEnabled(true); // default

        for (Attribute attr : attributes) {
            // Uid is server-generated; members are added via the Members API after create.
            if (attr.getName().equals(Uid.NAME) || attr.getName().equals(ATTR_MEMBERS)) {
                continue;
            }

            if (attr.getName().equals(Name.NAME)) {
                org.setName(AttributeUtil.getAsStringValue(attr));

            } else if (attr.getName().equals(ENABLE_NAME)) {
                org.setEnabled(AttributeUtil.getBooleanValue(attr));

            } else if (attr.getName().equals(ATTR_ALIAS)) {
                org.setAlias(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_DESCRIPTION)) {
                org.setDescription(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_REDIRECT_URL)) {
                org.setRedirectUrl(AttributeUtil.getStringValue(attr));

            } else if (attr.getName().equals(ATTR_DOMAINS)) {
                for (Object v : attr.getValue()) {
                    org.addDomain(parseDomain(v.toString()));
                }

            } else if (attr.getName().equals(ATTR_ATTRIBUTES)) {
                Map<String, List<String>> attrs = org.getAttributes();
                if (attrs == null) {
                    attrs = new HashMap<>();
                }
                for (Object v : attr.getValue()) {
                    Map.Entry<String, List<String>> e = parseKeyValueAttribute(v.toString());
                    attrs.put(e.getKey(), e.getValue());
                }
                org.setAttributes(attrs);

            } else {
                invalidSchema(attr.getName());
            }
        }

        return org;
    }

    /**
     * Parses a domain string in the format "name" or "name:verified".
     */
    private OrganizationDomainRepresentation parseDomain(String s) {
        OrganizationDomainRepresentation d = new OrganizationDomainRepresentation();
        int idx = s.indexOf(":");
        if (idx > 0) {
            d.setName(s.substring(0, idx));
            d.setVerified(Boolean.parseBoolean(s.substring(idx + 1)));
        } else {
            d.setName(s);
        }
        return d;
    }

    @Override
    public void updateOrganization(KeycloakSchema schema, String realmName, Uid uid,
                                   Set<AttributeDelta> modifications, OperationOptions options) throws UnknownUidException {
        List<String> addMemberIds = new ArrayList<>();
        List<String> removeMemberIds = new ArrayList<>();

        try {
            OrganizationResource orgResource = organizations(realmName).get(uid.getUidValue());
            OrganizationRepresentation current = orgResource.toRepresentation();
            boolean orgChanged = false;

            for (AttributeDelta delta : modifications) {
                if (delta.getName().equals(Name.NAME)) {
                    current.setName(AttributeDeltaUtil.getAsStringValue(delta));
                    orgChanged = true;

                } else if (delta.getName().equals(ENABLE_NAME)) {
                    current.setEnabled(AttributeDeltaUtil.getBooleanValue(delta));
                    orgChanged = true;

                } else if (delta.getName().equals(ATTR_ALIAS)) {
                    current.setAlias(AttributeDeltaUtil.getStringValue(delta));
                    orgChanged = true;

                } else if (delta.getName().equals(ATTR_DESCRIPTION)) {
                    current.setDescription(AttributeDeltaUtil.getStringValue(delta));
                    orgChanged = true;

                } else if (delta.getName().equals(ATTR_REDIRECT_URL)) {
                    current.setRedirectUrl(AttributeDeltaUtil.getStringValue(delta));
                    orgChanged = true;

                } else if (delta.getName().equals(ATTR_DOMAINS)) {
                    if (delta.getValuesToRemove() != null) {
                        for (Object v : delta.getValuesToRemove()) {
                            OrganizationDomainRepresentation existing =
                                    current.getDomain(parseDomain(v.toString()).getName());
                            if (existing != null) {
                                current.removeDomain(existing);
                            }
                        }
                    }
                    if (delta.getValuesToAdd() != null) {
                        for (Object v : delta.getValuesToAdd()) {
                            current.addDomain(parseDomain(v.toString()));
                        }
                    }
                    orgChanged = true;

                } else if (delta.getName().equals(ATTR_MEMBERS)) {
                    if (delta.getValuesToAdd() != null) {
                        for (Object v : delta.getValuesToAdd()) {
                            addMemberIds.add(v.toString());
                        }
                    }
                    if (delta.getValuesToRemove() != null) {
                        for (Object v : delta.getValuesToRemove()) {
                            removeMemberIds.add(v.toString());
                        }
                    }

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
                    orgChanged = true;

                } else {
                    invalidSchema(delta.getName());
                }
            }

            if (orgChanged) {
                Response res = orgResource.update(current);
                if (res.getStatus() != 204 && res.getStatus() != 200) {
                    throw new InvalidAttributeValueException("Failed to update organization: HTTP " + res.getStatus());
                }
            }

            // Member management is non-transactional with the org update
            for (String memberId : addMemberIds) {
                try {
                    orgResource.members().addMember(memberId);
                } catch (NotFoundException e) {
                    LOGGER.warn("User not found when adding to organization. userId: {0}, orgId: {1}",
                            memberId, uid.getUidValue());
                }
            }
            for (String memberId : removeMemberIds) {
                try {
                    orgResource.members().member(memberId).delete();
                } catch (NotFoundException e) {
                    LOGGER.warn("User not found when removing from organization. userId: {0}, orgId: {1}",
                            memberId, uid.getUidValue());
                }
            }

        } catch (NotFoundException e) {
            LOGGER.warn("Not found organization when updating. uid: {0}", uid);
            throw new UnknownUidException(uid, ORGANIZATION_OBJECT_CLASS);
        }
    }

    @Override
    public void deleteOrganization(KeycloakSchema schema, String realmName, Uid uid, OperationOptions options) throws UnknownUidException {
        try {
            Response res = organizations(realmName).get(uid.getUidValue()).delete();
            if (res.getStatus() == 404) {
                LOGGER.warn("[{0}] Not found organization when deleting. uid: {1}", instanceName, uid);
                throw new UnknownUidException(uid, ORGANIZATION_OBJECT_CLASS);
            }

        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Not found organization when deleting. uid: {1}", instanceName, uid);
            throw new UnknownUidException(uid, ORGANIZATION_OBJECT_CLASS);
        }
    }

    @Override
    public void getOrganizations(KeycloakSchema schema, String realmName, ResultsHandler handler, OperationOptions options,
                                 Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartial = shouldAllowPartialAttributeValues(options);

        List<OrganizationRepresentation> orgs = organizations(realmName).getAll();
        for (OrganizationRepresentation org : orgs) {
            if (!handler.handle(toConnectorObject(realmName, org, attributesToGet, allowPartial))) {
                KeycloakRESTUtils.signalAllResultsReturned(handler);
                return;
            }
        }

        KeycloakRESTUtils.signalAllResultsReturned(handler);
    }


    @Override
    public void getOrganization(KeycloakSchema schema, String realmName, Uid uid, ResultsHandler handler, OperationOptions options,
                                Set<String> attributesToGet, int queryPageSize) {
        try {
            OrganizationRepresentation org = organizations(realmName).get(uid.getUidValue()).toRepresentation();
            if (org == null) {
                LOGGER.warn("[{0}] Unknown organization uuid: {1}", instanceName, uid.getUidValue());
                return;
            }
            boolean allowPartial = shouldAllowPartialAttributeValues(options);
            handler.handle(toConnectorObject(realmName, org, attributesToGet, allowPartial));
        } catch (NotFoundException e) {
            LOGGER.warn("[{0}] Unknown organization uuid: {1}", instanceName, uid.getUidValue());
        }
    }

    @Override
    public void getOrganization(KeycloakSchema schema, String realmName, Name name, ResultsHandler handler, OperationOptions options,
                                Set<String> attributesToGet, int queryPageSize) {
        boolean allowPartial = shouldAllowPartialAttributeValues(options);

        // search() does substring matching, so we still need to filter by exact name
        List<OrganizationRepresentation> results = organizations(realmName).search(name.getNameValue(), true, 0, 100);
        for (OrganizationRepresentation org : results) {
            if (org.getName() != null && org.getName().equalsIgnoreCase(name.getNameValue())) {
                handler.handle(toConnectorObject(realmName, org, attributesToGet, allowPartial));
                return;
            }
        }
        LOGGER.warn("[{0}] Unknown organization name: {1}", instanceName, name.getNameValue());
    }

    private ConnectorObject toConnectorObject(String realmName, OrganizationRepresentation org,
                                              Set<String> attributesToGet, boolean allowPartial) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder()
                .setObjectClass(ORGANIZATION_OBJECT_CLASS)
                .setUid(org.getId())
                .setName(org.getName());

        if (shouldReturn(attributesToGet, ENABLE_NAME)) {
            builder.addAttribute(AttributeBuilder.buildEnabled(org.isEnabled()));
        }
        if (shouldReturn(attributesToGet, ATTR_ALIAS)) {
            builder.addAttribute(ATTR_ALIAS, org.getAlias());
        }
        if (shouldReturn(attributesToGet, ATTR_DESCRIPTION)) {
            builder.addAttribute(ATTR_DESCRIPTION, org.getDescription());
        }
        if (shouldReturn(attributesToGet, ATTR_REDIRECT_URL)) {
            builder.addAttribute(ATTR_REDIRECT_URL, org.getRedirectUrl());
        }

        if (shouldReturn(attributesToGet, ATTR_DOMAINS)) {
            Set<OrganizationDomainRepresentation> domains = org.getDomains();
            List<String> domainStrings = domains == null ? Collections.emptyList()
                    : domains.stream()
                    .map(d -> d.getName() + ":" + d.isVerified())
                    .collect(Collectors.toList());
            builder.addAttribute(ATTR_DOMAINS, domainStrings);
        }

        if (shouldReturn(attributesToGet, ATTR_ATTRIBUTES)) {
            Map<String, List<String>> attributes = org.getAttributes();
            List<String> generic = new ArrayList<>();
            if (attributes != null) {
                for (Map.Entry<String, List<String>> e : attributes.entrySet()) {
                    generic.add(String.format("%s=%s", e.getKey(), String.join("##", e.getValue())));
                }
            }
            builder.addAttribute(ATTR_ATTRIBUTES, generic);
        }

        if (allowPartial) {
            AttributeBuilder ab = new AttributeBuilder();
            ab.setName(ATTR_MEMBERS).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
            ab.addValue(Collections.EMPTY_LIST);
            builder.addAttribute(ab.build());
        } else if (attributesToGet != null && shouldReturn(attributesToGet, ATTR_MEMBERS)) {
            try {
                List<MemberRepresentation> members = organizations(realmName).get(org.getId()).members().getAll();
                builder.addAttribute(ATTR_MEMBERS, members.stream()
                        .map(MemberRepresentation::getId)
                        .collect(Collectors.toList()));
            } catch (Exception e) {
                LOGGER.warn("[{0}] Failed to fetch members for org {1}", instanceName, org.getId());
            }
        }

        return builder.build();
    }
}
