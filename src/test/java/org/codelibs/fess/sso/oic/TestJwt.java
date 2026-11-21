/*
 * Copyright 2012-2025 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.fess.sso.oic;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds signed JWTs and the JWKS documents that hold their keys, for the tests of back-channel logout. The provider
 * is this class: nothing is fetched from anywhere.
 */
final class TestJwt {

    static final String ISSUER = "https://idp.example.com/realms/test";

    static final String CLIENT_ID = "fess";

    static final String EVENT = LogoutTokenValidator.BACKCHANNEL_LOGOUT_EVENT;

    private TestJwt() {
    }

    static KeyPair rsaKey() {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyPair ecKey(final String curve) {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            return generator.generateKeyPair();
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The claims of a valid logout token for the session {@code sid-1} of the subject {@code user-1}, issued at {@code now}. */
    static Map<String, Object> logoutClaims(final long now) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
        claims.put("aud", CLIENT_ID);
        claims.put("iat", now);
        claims.put("exp", now + 120);
        claims.put("jti", "jti-" + System.nanoTime());
        claims.put("sub", "user-1");
        claims.put("sid", "sid-1");
        claims.put("events", Map.of(EVENT, Map.of()));
        return claims;
    }

    /** Signs with RS256 under the key id {@code kid}. */
    static String rs256(final PrivateKey key, final String kid, final Map<String, Object> claims) {
        return sign("RS256", "SHA256withRSA", key, header("RS256", kid), claims);
    }

    /** Signs with ES256 under the key id {@code kid}. */
    static String es256(final PrivateKey key, final String kid, final Map<String, Object> claims) {
        return sign("ES256", "SHA256withECDSAinP1363Format", key, header("ES256", kid), claims);
    }

    static String header(final String alg, final String kid) {
        final Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", "JWT");
        if (kid != null) {
            header.put("kid", kid);
        }
        return json(header);
    }

    static String sign(final String alg, final String jcaName, final PrivateKey key, final String headerJson,
            final Map<String, Object> claims) {
        final String signed =
                base64Url(headerJson.getBytes(StandardCharsets.UTF_8)) + "." + base64Url(json(claims).getBytes(StandardCharsets.UTF_8));
        try {
            final Signature signature = Signature.getInstance(jcaName);
            signature.initSign(key);
            signature.update(signed.getBytes(StandardCharsets.US_ASCII));
            return signed + "." + base64Url(signature.sign());
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(alg, e);
        }
    }

    /** A token with the given header and claims and an arbitrary signature part. */
    static String unsigned(final String headerJson, final Map<String, Object> claims, final String signaturePart) {
        return base64Url(headerJson.getBytes(StandardCharsets.UTF_8)) + "." + base64Url(json(claims).getBytes(StandardCharsets.UTF_8)) + "."
                + signaturePart;
    }

    @SafeVarargs
    static String jwks(final Map<String, Object>... keys) {
        return json(Map.of("keys", List.of(keys)));
    }

    static Map<String, Object> rsaJwk(final RSAPublicKey key, final String kid) {
        final Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        if (kid != null) {
            jwk.put("kid", kid);
        }
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("n", base64Url(unsignedBytes(key.getModulus())));
        jwk.put("e", base64Url(unsignedBytes(key.getPublicExponent())));
        return jwk;
    }

    static Map<String, Object> ecJwk(final ECPublicKey key, final String kid, final String crv) {
        final Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        if (kid != null) {
            jwk.put("kid", kid);
        }
        jwk.put("crv", crv);
        jwk.put("x", base64Url(unsignedBytes(key.getW().getAffineX())));
        jwk.put("y", base64Url(unsignedBytes(key.getW().getAffineY())));
        return jwk;
    }

    private static byte[] unsignedBytes(final BigInteger value) {
        final byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            final byte[] stripped = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, stripped, 0, stripped.length);
            return stripped;
        }
        return bytes;
    }

    static String base64Url(final byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** A JSON text of maps, lists, strings, numbers and booleans. */
    static String json(final Object value) {
        if (value instanceof final Map<?, ?> map) {
            final StringBuilder buf = new StringBuilder("{");
            for (final Map.Entry<?, ?> entry : map.entrySet()) {
                if (buf.length() > 1) {
                    buf.append(',');
                }
                buf.append(json(String.valueOf(entry.getKey()))).append(':').append(json(entry.getValue()));
            }
            return buf.append('}').toString();
        }
        if (value instanceof final List<?> list) {
            final StringBuilder buf = new StringBuilder("[");
            for (final Object element : list) {
                if (buf.length() > 1) {
                    buf.append(',');
                }
                buf.append(json(element));
            }
            return buf.append(']').toString();
        }
        if (value instanceof final String text) {
            return '"' + text.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
        }
        return String.valueOf(value);
    }
}
