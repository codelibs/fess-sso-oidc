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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests how the keys of the provider are read and when the JWKS document is fetched again.
 */
public class JwksKeySourceTest {

    private static final java.security.KeyPair RSA_1 = TestJwt.rsaKey();

    private static final java.security.KeyPair RSA_2 = TestJwt.rsaKey();

    private final AtomicLong now = new AtomicLong(1_000_000_000L);

    private final AtomicInteger fetches = new AtomicInteger();

    private final AtomicReference<String> document = new AtomicReference<>();

    private JwksKeySource source;

    @BeforeEach
    public void setUp() {
        document.set(TestJwt.jwks(TestJwt.rsaJwk((RSAPublicKey) RSA_1.getPublic(), "k1")));
        final OpenIdConnectAuthenticator json = new OpenIdConnectAuthenticator();
        source = new JwksKeySource(() -> "https://idp.example.com/jwks", url -> {
            fetches.incrementAndGet();
            final String text = document.get();
            if (text == null) {
                throw new IllegalStateException("The JWKS endpoint answered HTTP 503.");
            }
            return text;
        }, json::parseJsonObject, now::get);
    }

    @Test
    public void test_theDocumentIsFetchedOnceWhileItIsFresh() {
        assertEquals(1, source.find("k1", "RSA").size());
        assertEquals(1, source.find("k1", "RSA").size());
        assertEquals(1, fetches.get());
    }

    @Test
    public void test_anUnknownKidDoesNotFetchTheDocumentAgainAtOnce() {
        assertEquals(1, source.find("k1", "RSA").size());

        // anyone can send a token with a kid of his own, and each would otherwise be a request to the provider
        for (int i = 0; i < 20; i++) {
            assertThrows(IllegalStateException.class, () -> source.find("made-up", "RSA"));
        }
        assertEquals(1, fetches.get());
    }

    @Test
    public void test_aRotatedKeyIsFoundOnceTheIntervalHasPassed() {
        source.find("k1", "RSA");
        document.set(TestJwt.jwks(TestJwt.rsaJwk((RSAPublicKey) RSA_1.getPublic(), "k1"),
                TestJwt.rsaJwk((RSAPublicKey) RSA_2.getPublic(), "k2")));
        assertThrows(IllegalStateException.class, () -> source.find("k2", "RSA"));

        now.addAndGet(JwksKeySource.MIN_FETCH_INTERVAL_MILLIS);

        assertEquals(1, source.find("k2", "RSA").size());
        assertEquals(2, fetches.get());
    }

    @Test
    public void test_aFailedFetchCountsForTheIntervalToo() {
        document.set(null);
        for (int i = 0; i < 5; i++) {
            assertThrows(IllegalStateException.class, () -> source.find("k1", "RSA"));
        }
        assertEquals(1, fetches.get());

        document.set(TestJwt.jwks(TestJwt.rsaJwk((RSAPublicKey) RSA_1.getPublic(), "k1")));
        now.addAndGet(JwksKeySource.MIN_FETCH_INTERVAL_MILLIS);
        assertEquals(1, source.find("k1", "RSA").size());
    }

    @Test
    public void test_theKeysAreNotTrustedPastTheirAgeWhenTheDocumentCannotBeRead() {
        source.find("k1", "RSA");
        document.set(null);

        now.addAndGet(JwksKeySource.MAX_AGE_MILLIS);
        assertThrows(IllegalStateException.class, () -> source.find("k1", "RSA"));
        // and not on the next try either, which is too soon to fetch again
        assertThrows(IllegalStateException.class, () -> source.find("k1", "RSA"));
    }

    @Test
    public void test_aKeyIsReadAgainAfterItsAge() {
        source.find("k1", "RSA");
        document.set(TestJwt.jwks(TestJwt.rsaJwk((RSAPublicKey) RSA_2.getPublic(), "k1")));

        now.addAndGet(JwksKeySource.MAX_AGE_MILLIS);

        assertEquals(RSA_2.getPublic(), source.find("k1", "RSA").get(0));
    }

    @Test
    public void test_onlyTheKeysThatMaySignAreRead() {
        final Map<String, Object> encryption = TestJwt.rsaJwk((RSAPublicKey) RSA_1.getPublic(), "enc");
        encryption.put("use", "enc");
        final Map<String, Object> oct = new LinkedHashMap<>();
        oct.put("kty", "oct");
        oct.put("kid", "secret");
        oct.put("k", "AAAA");
        final Map<String, Object> badCurve = TestJwt.ecJwk((ECPublicKey) TestJwt.ecKey("secp256r1").getPublic(), "bad", "P-256");
        badCurve.put("crv", "secp256k1");
        final Map<String, Object> notOnTheCurve = TestJwt.ecJwk((ECPublicKey) TestJwt.ecKey("secp256r1").getPublic(), "off", "P-256");
        notOnTheCurve.put("y", TestJwt.base64Url(new byte[] { 1, 2, 3 }));
        final Map<String, Object> noModulus = new LinkedHashMap<>();
        noModulus.put("kty", "RSA");
        noModulus.put("kid", "nomodulus");
        document.set(TestJwt.jwks(encryption, oct, badCurve, notOnTheCurve, noModulus,
                TestJwt.rsaJwk((RSAPublicKey) RSA_2.getPublic(), "good")));

        assertEquals(1, source.find("good", "RSA").size());
        now.addAndGet(JwksKeySource.MIN_FETCH_INTERVAL_MILLIS);
        for (final String kid : new String[] { "enc", "secret", "bad", "off", "nomodulus" }) {
            assertThrows(IllegalStateException.class, () -> source.find(kid, "RSA"), kid);
            now.addAndGet(JwksKeySource.MIN_FETCH_INTERVAL_MILLIS);
        }
    }

    @Test
    public void test_aDocumentThatIsNotAJwksHasNoKeys() {
        document.set("{\"keys\":\"none\"}");
        assertThrows(IllegalStateException.class, () -> source.find("k1", "RSA"));
        now.addAndGet(JwksKeySource.MIN_FETCH_INTERVAL_MILLIS);
        document.set("not json");
        assertThrows(IllegalStateException.class, () -> source.find("k1", "RSA"));
    }

    @Test
    public void test_aBlankUriFetchesNothing() {
        final JwksKeySource blank = new JwksKeySource(() -> " ", url -> {
            fetches.incrementAndGet();
            return "{}";
        }, new OpenIdConnectAuthenticator()::parseJsonObject, now::get);

        assertThrows(IllegalStateException.class, () -> blank.find("k1", "RSA"));
        assertEquals(0, fetches.get());
    }
}
