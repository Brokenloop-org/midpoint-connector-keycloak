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

import org.brokenloop.midpoint.keycloak.connector.FederatedIdentityCodec;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;

import jakarta.ws.rs.core.Response;
import java.util.*;

/**
 * Reads and applies federated identity links of a user. Links are identified by identity provider alias.
 */
final class FederatedIdentityOps {

    private static final Log LOGGER = Log.getLog(FederatedIdentityOps.class);

    private FederatedIdentityOps() {
    }

    /**
     * Aliases to unlink and links to add, in that order of application. {@code removed} holds the links
     * being unlinked so they can be restored if an add fails.
     */
    record Plan(List<String> remove, List<FederatedIdentityRepresentation> add,
                Map<String, FederatedIdentityRepresentation> removed) {
        boolean isEmpty() {
            return remove.isEmpty() && add.isEmpty();
        }
    }

    /** Parses the values and checks that every identity provider alias exists in the realm. */
    static List<FederatedIdentityRepresentation> parseAndValidate(RealmResource realm, Collection<?> values) {
        List<FederatedIdentityRepresentation> reps = new ArrayList<>();
        if (values == null) {
            return reps;
        }
        Set<String> aliases = null;
        for (Object v : values) {
            if (v == null) {
                continue;
            }
            FederatedIdentityRepresentation rep = FederatedIdentityCodec.parse(v.toString());
            if (aliases == null) {
                aliases = new HashSet<>();
                for (IdentityProviderRepresentation idp : realm.identityProviders().findAll()) {
                    aliases.add(idp.getAlias());
                }
            }
            if (!aliases.contains(rep.getIdentityProvider())) {
                throw new InvalidAttributeValueException(
                        "Unknown identity provider alias '" + rep.getIdentityProvider() + "'");
            }
            for (FederatedIdentityRepresentation seen : reps) {
                if (seen.getIdentityProvider().equals(rep.getIdentityProvider())) {
                    throw new InvalidAttributeValueException("Several federated identities for identity provider '"
                            + rep.getIdentityProvider() + "'; a user can have one link per identity provider");
                }
            }
            reps.add(rep);
        }
        return reps;
    }

    static List<FederatedIdentityRepresentation> read(UserResource user) {
        List<FederatedIdentityRepresentation> links = user.getFederatedIdentity();
        return links == null ? List.of() : links;
    }

    /** Diff by alias between the current links and the state the delta asks for. */
    static Plan plan(RealmResource realm, List<FederatedIdentityRepresentation> current, AttributeDelta delta) {
        Map<String, FederatedIdentityRepresentation> target = new LinkedHashMap<>();
        if (delta.getValuesToReplace() != null) {
            for (FederatedIdentityRepresentation r : parseAndValidate(realm, delta.getValuesToReplace())) {
                target.put(r.getIdentityProvider(), r);
            }
        } else {
            for (FederatedIdentityRepresentation r : current) {
                target.put(r.getIdentityProvider(), r);
            }
            // Validate the additions before looking at removals so that nothing is written on bad input.
            List<FederatedIdentityRepresentation> additions = parseAndValidate(realm, delta.getValuesToAdd());
            if (delta.getValuesToRemove() != null) {
                for (Object v : delta.getValuesToRemove()) {
                    if (v == null) {
                        continue;
                    }
                    FederatedIdentityRepresentation r = FederatedIdentityCodec.parse(v.toString());
                    FederatedIdentityRepresentation now = target.get(r.getIdentityProvider());
                    if (now != null && Objects.equals(now.getUserId(), r.getUserId())) {
                        target.remove(r.getIdentityProvider());
                    } else {
                        LOGGER.warn("Ignoring removal of identity provider link \"{0}\"/\"{1}\": the current link is {2}",
                                r.getIdentityProvider(), r.getUserId(),
                                now == null ? "absent" : "to another user id");
                    }
                }
            }
            for (FederatedIdentityRepresentation r : additions) {
                target.put(r.getIdentityProvider(), r);
            }
        }

        Map<String, FederatedIdentityRepresentation> cur = new LinkedHashMap<>();
        for (FederatedIdentityRepresentation r : current) {
            cur.put(r.getIdentityProvider(), r);
        }
        List<String> remove = new ArrayList<>();
        List<FederatedIdentityRepresentation> add = new ArrayList<>();
        for (String alias : cur.keySet()) {
            FederatedIdentityRepresentation t = target.get(alias);
            if (t == null || !same(t, cur.get(alias))) {
                remove.add(alias);
            }
        }
        for (Map.Entry<String, FederatedIdentityRepresentation> e : target.entrySet()) {
            FederatedIdentityRepresentation c = cur.get(e.getKey());
            if (c == null || !same(e.getValue(), c)) {
                add.add(e.getValue());
            }
        }
        Map<String, FederatedIdentityRepresentation> removed = new LinkedHashMap<>();
        for (String alias : remove) {
            removed.put(alias, cur.get(alias));
        }
        return new Plan(remove, add, removed);
    }

    static void apply(UserResource user, Plan plan) {
        for (String alias : plan.remove()) {
            user.removeFederatedIdentity(alias);
        }
        for (FederatedIdentityRepresentation rep : plan.add()) {
            try {
                add(user, List.of(rep));
            } catch (RuntimeException e) {
                // Best effort, for any failure: put back the link that was removed for this alias so the
                // user is not left unlinked. A failing restore is logged and never masks the original error.
                FederatedIdentityRepresentation old = plan.removed().get(rep.getIdentityProvider());
                if (old != null) {
                    restore(user, old);
                }
                throw e;
            }
        }
    }

    private static void restore(UserResource user, FederatedIdentityRepresentation old) {
        try (Response res = user.addFederatedIdentity(old.getIdentityProvider(), old)) {
            if (res.getStatus() != Response.Status.NO_CONTENT.getStatusCode()
                    && res.getStatus() != Response.Status.CREATED.getStatusCode()) {
                LOGGER.warn("Could not restore the identity provider link \"{0}\" after a failed update. status: {1}",
                        old.getIdentityProvider(), res.getStatus());
            }
        } catch (RuntimeException e) {
            LOGGER.warn(e, "Could not restore the identity provider link \"{0}\" after a failed update",
                    old.getIdentityProvider());
        }
    }

    static void add(UserResource user, List<FederatedIdentityRepresentation> links) {
        for (FederatedIdentityRepresentation rep : links) {
            try (Response res = user.addFederatedIdentity(rep.getIdentityProvider(), rep)) {
                int status = res.getStatus();
                if (status == Response.Status.NO_CONTENT.getStatusCode()
                        || status == Response.Status.CREATED.getStatusCode()) {
                    continue;
                }
                String target = String.format("identity provider \"%s\" link \"%s\"",
                        rep.getIdentityProvider(), rep.getUserId());
                if (status == Response.Status.CONFLICT.getStatusCode()) {
                    throw new AlreadyExistsException(String.format(
                            "Federated identity %s/%s is already linked to another user",
                            rep.getIdentityProvider(), rep.getUserId()));
                }
                if (status >= 400 && status < 500) {
                    throw new InvalidAttributeValueException(String.format(
                            "Keycloak rejected the %s. status: %d", target, status));
                }
                throw new ConnectorException(String.format(
                        "Keycloak returns unexpected error when linking identity provider \"%s\". status: %d",
                        rep.getIdentityProvider(), status));
            }
        }
    }

    private static boolean same(FederatedIdentityRepresentation a, FederatedIdentityRepresentation b) {
        return Objects.equals(a.getUserId(), b.getUserId()) && Objects.equals(a.getUserName(), b.getUserName());
    }
}
