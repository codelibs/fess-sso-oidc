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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codelibs.core.lang.StringUtil;

/**
 * The signature keys of the OpenID provider, read from the {@code jwks_uri} document (RFC 7517).
 *
 * <p>The keys are kept for {@value #MAX_AGE_MILLIS} ms. A key that is not among them is looked for in a
 * fresh copy of the document, but never more often than once per {@value #MIN_FETCH_INTERVAL_MILLIS} ms, because
 * the token that names the unknown key arrives on an anonymous endpoint and each lookup would otherwise be a request
 * to the provider that anyone can trigger. A failed fetch counts as a fetch for that limit.</p>
 *
 * <p>Only RSA and EC (P-256, P-384, P-521) keys that may sign ({@code use} is absent or {@code sig}) are read; any
 * other entry of the document is ignored.</p>
 */
public class JwksKeySource {

    private static final Logger logger = LogManager.getLogger(JwksKeySource.class);

    /** How long the keys of one fetch are used before the document is fetched again. */
    protected static final long MAX_AGE_MILLIS = 60 * 60 * 1000L;

    /** The shortest time between two fetches of the document. */
    protected static final long MIN_FETCH_INTERVAL_MILLIS = 60 * 1000L;

    private final Supplier<String> uri;

    private final Function<String, String> fetcher;

    private final Function<String, Map<String, Object>> jsonParser;

    private final LongSupplier clock;

    private Map<String, PublicKey> keysByKid = Map.of();

    private List<PublicKey> keysWithoutKid = List.of();

    private long fetchedAt;

    private long attemptedAt;

    /**
     * Creates the source.
     *
     * @param uri supplies the current {@code jwks_uri}; read at every fetch, so a change of the setting is seen
     * @param fetcher reads the document at a URL; throws {@link IllegalStateException} if it cannot
     * @param jsonParser parses a JSON object
     * @param clock supplies the current time in milliseconds
     */
    public JwksKeySource(final Supplier<String> uri, final Function<String, String> fetcher,
            final Function<String, Map<String, Object>> jsonParser, final LongSupplier clock) {
        this.uri = uri;
        this.fetcher = fetcher;
        this.jsonParser = jsonParser;
        this.clock = clock;
    }

    /**
     * Finds the key that a token with this {@code kid} header is signed with.
     *
     * @param kid the {@code kid} of the JWS header, or null if there is none
     * @param keyType the key type the algorithm of the token needs, {@code RSA} or {@code EC}
     * @return the keys that may have signed the token: the key with the {@code kid}; or, for a token without
     *         {@code kid}, every key of the type that has none
     * @throws IllegalStateException if the document cannot be read or holds no such key
     */
    public synchronized List<PublicKey> find(final String kid, final String keyType) {
        final long now = clock.getAsLong();
        List<PublicKey> found = lookup(kid, keyType);
        final boolean stale = now - fetchedAt >= MAX_AGE_MILLIS;
        if ((found.isEmpty() || stale) && now - attemptedAt >= MIN_FETCH_INTERVAL_MILLIS) {
            attemptedAt = now;
            refresh();
            fetchedAt = now;
            found = lookup(kid, keyType);
        } else if (stale) {
            // Too soon to ask again; a document that could not be read is not trusted past its age.
            keysByKid = Map.of();
            keysWithoutKid = List.of();
            found = List.of();
        }
        if (found.isEmpty()) {
            throw new IllegalStateException("The JWKS document has no usable " + keyType + " key for the kid of the token.");
        }
        return found;
    }

    private List<PublicKey> lookup(final String kid, final String keyType) {
        if (StringUtil.isNotBlank(kid)) {
            final PublicKey key = keysByKid.get(kid);
            return key != null && matches(key, keyType) ? List.of(key) : List.of();
        }
        return keysWithoutKid.stream().filter(key -> matches(key, keyType)).toList();
    }

    private static boolean matches(final PublicKey key, final String keyType) {
        return keyType.equals(key.getAlgorithm());
    }

    @SuppressWarnings("unchecked")
    private void refresh() {
        final String url = uri.get();
        if (StringUtil.isBlank(url)) {
            throw new IllegalStateException("The JWKS URI is not set.");
        }
        final Map<String, Object> document;
        try {
            document = jsonParser.apply(fetcher.apply(url.trim()));
        } catch (final IllegalArgumentException e) {
            throw new IllegalStateException("The JWKS document is not a JSON object.", e);
        }
        final Map<String, PublicKey> byKid = new HashMap<>();
        final List<PublicKey> noKid = new ArrayList<>();
        if (document.get("keys") instanceof final List<?> keys) {
            for (final Object entry : keys) {
                if (!(entry instanceof final Map<?, ?> jwk)) {
                    continue;
                }
                final PublicKey key = toPublicKey((Map<String, Object>) jwk);
                if (key == null) {
                    continue;
                }
                if (jwk.get("kid") instanceof final String id && StringUtil.isNotBlank(id)) {
                    byKid.putIfAbsent(id, key);
                } else {
                    noKid.add(key);
                }
            }
        }
        keysByKid = Map.copyOf(byKid);
        keysWithoutKid = List.copyOf(noKid);
        if (logger.isDebugEnabled()) {
            logger.debug("Read the JWKS document: keys with kid={}, keys without kid={}", byKid.size(), noKid.size());
        }
    }

    /**
     * Converts a JWK to a public key.
     *
     * @param jwk the JWK
     * @return the key, or null if it is not an RSA or EC signature key this class reads, or is malformed
     */
    protected static PublicKey toPublicKey(final Map<String, Object> jwk) {
        final Object use = jwk.get("use");
        if (use != null && !"sig".equals(use)) {
            return null;
        }
        try {
            if ("RSA".equals(jwk.get("kty"))) {
                final BigInteger n = integer(jwk.get("n"));
                final BigInteger e = integer(jwk.get("e"));
                return n == null || e == null ? null : KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
            }
            if ("EC".equals(jwk.get("kty"))) {
                final String curve = curveName(jwk.get("crv"));
                final BigInteger x = integer(jwk.get("x"));
                final BigInteger y = integer(jwk.get("y"));
                if (curve == null || x == null || y == null) {
                    return null;
                }
                final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(curve));
                final ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
                return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
            }
        } catch (final GeneralSecurityException | IllegalArgumentException e) {
            // A point that is not on the curve, or a modulus that is not a number: the entry is of no use.
            if (logger.isDebugEnabled()) {
                logger.debug("A JWK is ignored: {}", e.getMessage());
            }
        }
        return null;
    }

    private static String curveName(final Object crv) {
        if ("P-256".equals(crv)) {
            return "secp256r1";
        }
        if ("P-384".equals(crv)) {
            return "secp384r1";
        }
        if ("P-521".equals(crv)) {
            return "secp521r1";
        }
        return null;
    }

    private static BigInteger integer(final Object base64Url) {
        if (!(base64Url instanceof final String text) || text.isEmpty()) {
            return null;
        }
        return new BigInteger(1, Base64.getUrlDecoder().decode(text));
    }

    /**
     * Reads a response body that is not larger than a limit.
     *
     * @param stream the stream of the response
     * @param limit the most bytes accepted
     * @return the body as UTF-8 text
     * @throws IOException if the stream fails
     * @throws IllegalStateException if the body is longer than the limit
     */
    protected static String readLimited(final InputStream stream, final int limit) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] buffer = new byte[4096];
        int read;
        while ((read = stream.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
            if (out.size() > limit) {
                throw new IllegalStateException("The JWKS document is longer than " + limit + " bytes.");
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }
}
