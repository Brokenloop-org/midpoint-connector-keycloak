package org.brokenloop.midpoint.keycloak.connector;

import org.identityconnectors.framework.common.objects.*;

import java.time.ZonedDateTime;
import java.util.*;

public class ConnIdTestFixtures {

    public static AttributeInfo stringAttrInfo(String name) {
        return AttributeInfoBuilder.define(name).build();
    }

    public static AttributeInfo intAttrInfo(String name) {
        return AttributeInfoBuilder.define(name).setType(Integer.class).build();
    }

    public static AttributeInfo booleanAttrInfo(String name) {
        return AttributeInfoBuilder.define(name).setType(Boolean.class).build();
    }

    public static AttributeInfo dateTimeAttrInfo(String name) {
        return AttributeInfoBuilder.define(name).setType(ZonedDateTime.class).build();
    }

    public static AttributeInfo multiValuedAttrInfo(String name) {
        return AttributeInfoBuilder.define(name).setMultiValued(true).build();
    }

    public static AttributeInfo returnedByDefaultAttrInfo(String name) {
        return AttributeInfoBuilder.define(name).setReturnedByDefault(true).build();
    }

    public static AttributeInfo notReturnedByDefaultAttrInfo(String name) {
        return AttributeInfoBuilder.define(name).setReturnedByDefault(false).build();
    }

    public static Map.Entry<String, List<String>> entry(String key, String... values) {
        return Map.of(key, Arrays.asList(values)).entrySet().iterator().next();
    }

    public static Map.Entry<String, List<String>> entryWithEmptyList(String key) {
        return Map.of(key, Collections.<String>emptyList()).entrySet().iterator().next();
    }

    public static Map<String, AttributeInfo> schemaMap(AttributeInfo... infos) {
        Map<String, AttributeInfo> map = new HashMap<>();
        for (AttributeInfo info : infos) {
            map.put(info.getName(), info);
        }
        return map;
    }

    public static OperationOptions emptyOptions() {
        return new OperationOptionsBuilder().build();
    }

    public static OperationOptions optionsWithReturnDefault() {
        return new OperationOptionsBuilder()
                .setReturnDefaultAttributes(true)
                .build();
    }

    public static OperationOptions optionsWithAttrsToGet(String... attrs) {
        return new OperationOptionsBuilder()
                .setAttributesToGet(attrs)
                .build();
    }

    public static OperationOptions optionsWithPartialValues() {
        return new OperationOptionsBuilder()
                .setAllowPartialAttributeValues(true)
                .build();
    }

    public static Optional<AttributeInfo> findAttribute(ObjectClassInfo oci, String name) {
        return oci.getAttributeInfo().stream()
                .filter(ai -> ai.getName().equals(name))
                .findFirst();
    }
}
