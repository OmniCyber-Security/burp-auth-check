package com.omnicybersecurity.authcheck.model;

import burp.api.montoya.http.message.params.HttpParameterType;

/**
 * A request parameter an auth script wants set (URL, body, cookie, JSON, ...).
 *
 * @param type  where the parameter lives
 * @param name  parameter name
 * @param value parameter value
 */
public record ParamSpec(HttpParameterType type, String name, String value) {

    public static ParamSpec of(String type, String name, String value) {
        HttpParameterType parsed;
        try {
            parsed = HttpParameterType.valueOf(type.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown parameter type '" + type
                    + "'. Use one of: URL, BODY, COOKIE, JSON, XML, XML_ATTRIBUTE, MULTIPART_ATTRIBUTE");
        }
        return new ParamSpec(parsed, name, value);
    }
}
