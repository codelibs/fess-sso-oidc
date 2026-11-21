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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.codelibs.fess.sso.oic.LogoutTokenValidator.LogoutToken;
import org.codelibs.fess.sso.oic.LogoutTokenValidator.LogoutTokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests the validation of a logout token (OpenID Connect Back-Channel Logout 1.0, section 2.6) against a provider that is
 * a key pair of the test.
 */
public class LogoutTokenValidatorTest {

    private static final long NOW = 1_800_000_000L;

    private static final KeyPair RSA = TestJwt.rsaKey();

    private static final KeyPair OTHER_RSA = TestJwt.rsaKey();

    private static final KeyPair EC = TestJwt.ecKey("secp256r1");

    private final AtomicInteger fetches = new AtomicInteger();

    private LogoutTokenValidator validator;

    @BeforeEach
    public void setUp() {
        final String jwks = TestJwt.jwks(TestJwt.rsaJwk((RSAPublicKey) RSA.getPublic(), "rsa-1"),
                TestJwt.ecJwk((ECPublicKey) EC.getPublic(), "ec-1", "P-256"));
        final OpenIdConnectAuthenticator json = new OpenIdConnectAuthenticator();
        final JwksKeySource keys = new JwksKeySource(() -> "https://idp.example.com/jwks", url -> {
            fetches.incrementAndGet();
            return jwks;
        }, json::parseJsonObject, () -> NOW * 1000);
        validator = new LogoutTokenValidator(json::parseJsonObject, keys);
    }

    private LogoutToken validate(final String token) {
        return validator.validate(token, TestJwt.ISSUER, TestJwt.CLIENT_ID, NOW);
    }

    private void assertRefused(final String token, final String reason) {
        final LogoutTokenException e = assertThrows(LogoutTokenException.class, () -> validate(token), reason);
        assertTrue(e.getMessage() != null && (token == null || token.isEmpty() || !e.getMessage().contains(token)),
                "the message repeats the token");
    }

    private static String rs256(final Map<String, Object> claims) {
        return TestJwt.rs256(RSA.getPrivate(), "rsa-1", claims);
    }

    // ===================================================================================
    //                                                                          Accepted
    //                                                                          ========
    @Test
    public void test_aTokenWithSidAndSub() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);

        final LogoutToken token = validate(rs256(claims));

        assertEquals(TestJwt.ISSUER, token.issuer());
        assertEquals("sid-1", token.sessionId());
        assertEquals("user-1", token.subject());
        assertEquals(claims.get("jti"), token.jti());
        assertEquals(NOW, token.issuedAt());
    }

    @Test
    public void test_aTokenWithSidOnly() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.remove("sub");

        final LogoutToken token = validate(rs256(claims));

        assertEquals("sid-1", token.sessionId());
        assertNull(token.subject());
    }

    @Test
    public void test_aTokenWithSubOnly() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.remove("sid");

        final LogoutToken token = validate(rs256(claims));

        assertEquals("user-1", token.subject());
        assertNull(token.sessionId());
    }

    @Test
    public void test_anAudienceThatIsAnArrayWithTheClient() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.put("aud", List.of("another-client", TestJwt.CLIENT_ID));

        assertEquals("sid-1", validate(rs256(claims)).sessionId());
    }

    @Test
    public void test_anEs256Token() {
        assertEquals("sid-1", validate(TestJwt.es256(EC.getPrivate(), "ec-1", TestJwt.logoutClaims(NOW))).sessionId());
    }

    @Test
    public void test_aTokenWithoutKidIsCheckedAgainstTheKeysWithoutOne() {
        final String jwks = TestJwt.jwks(TestJwt.rsaJwk((RSAPublicKey) RSA.getPublic(), null));
        final OpenIdConnectAuthenticator json = new OpenIdConnectAuthenticator();
        final LogoutTokenValidator noKid = new LogoutTokenValidator(json::parseJsonObject,
                new JwksKeySource(() -> "https://idp.example.com/jwks", url -> jwks, json::parseJsonObject, () -> NOW * 1000));

        final String token = TestJwt.rs256(RSA.getPrivate(), null, TestJwt.logoutClaims(NOW));

        assertEquals("sid-1", noKid.validate(token, TestJwt.ISSUER, TestJwt.CLIENT_ID, NOW).sessionId());
    }

    @Test
    public void test_theClockSkewIsTolerated() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.put("iat", NOW + 200); // a provider whose clock is ahead
        claims.put("exp", NOW - 200); // and one that is behind

        assertEquals("sid-1", validate(rs256(claims)).sessionId());
    }

    // ===================================================================================
    //                                                                          Signature
    //                                                                          =========
    @Test
    public void test_aTokenSignedByAnotherKeyIsRefused() {
        assertRefused(TestJwt.rs256(OTHER_RSA.getPrivate(), "rsa-1", TestJwt.logoutClaims(NOW)), "signature of another key");
    }

    @Test
    public void test_aTokenWhoseClaimsWereChangedIsRefused() {
        final String token = rs256(TestJwt.logoutClaims(NOW));
        final Map<String, Object> other = TestJwt.logoutClaims(NOW);
        other.put("sid", "sid-of-someone-else");
        final String[] parts = token.split("\\.");
        final String forged =
                parts[0] + "." + TestJwt.base64Url(TestJwt.json(other).getBytes(java.nio.charset.StandardCharsets.UTF_8)) + "." + parts[2];

        assertRefused(forged, "claims changed after signing");
    }

    @Test
    public void test_aTokenWithAnEmptySignatureIsRefused() {
        assertRefused(TestJwt.unsigned(TestJwt.header("RS256", "rsa-1"), TestJwt.logoutClaims(NOW), ""), "empty signature");
    }

    @Test
    public void test_algNoneIsRefused() {
        assertRefused(TestJwt.unsigned(TestJwt.header("none", null), TestJwt.logoutClaims(NOW), ""), "alg none");
    }

    @Test
    public void test_anHmacTokenIsRefusedEvenIfItIsSignedWithThePublicKey() {
        // the classic confusion: HS256 with the modulus of the RSA key as the secret
        assertRefused(TestJwt.unsigned(TestJwt.header("HS256", "rsa-1"), TestJwt.logoutClaims(NOW), TestJwt.base64Url(new byte[32])),
                "alg HS256");
    }

    @Test
    public void test_anAlgorithmThatDoesNotMatchTheKeyTypeIsRefused() {
        // an ES256 token under the kid of an RSA key
        assertRefused(TestJwt.es256(EC.getPrivate(), "rsa-1", TestJwt.logoutClaims(NOW)), "key type");
    }

    @Test
    public void test_anUnknownKidIsRefused() {
        assertRefused(TestJwt.rs256(RSA.getPrivate(), "unknown", TestJwt.logoutClaims(NOW)), "unknown kid");
    }

    @Test
    public void test_aTokenThatIsNotAJwsIsRefused() {
        assertRefused("not-a-token", "no dots");
        assertRefused("a.b", "two parts");
        assertRefused("a.b.c.d", "four parts");
        assertRefused("!!!.???.***", "not base64url");
        assertRefused("", "empty");
        assertRefused(null, "null");
        assertRefused("a".repeat(LogoutTokenValidator.MAX_TOKEN_LENGTH + 1), "too long");
    }

    @Test
    public void test_aHeaderOrClaimsThatAreNotAJsonObjectAreRefused() {
        final String notObject = TestJwt.base64Url("[1,2]".getBytes());
        assertRefused(notObject + "." + notObject + ".AAAA", "array");
        final String nonsense = TestJwt.base64Url("{\"alg\":".getBytes());
        assertRefused(nonsense + "." + nonsense + ".AAAA", "truncated JSON");
    }

    // ===================================================================================
    //                                                                            Claims
    //                                                                            ======
    @Test
    public void test_anotherIssuerIsRefused() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.put("iss", TestJwt.ISSUER + "/");

        assertRefused(rs256(claims), "iss");
        claims.remove("iss");
        assertRefused(rs256(claims), "no iss");
    }

    @Test
    public void test_anotherAudienceIsRefused() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.put("aud", "another-client");
        assertRefused(rs256(claims), "aud");
        claims.put("aud", List.of("a", "b"));
        assertRefused(rs256(claims), "aud array");
        claims.remove("aud");
        assertRefused(rs256(claims), "no aud");
    }

    @Test
    public void test_anExpiredTokenIsRefused() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.put("iat", NOW - 1000);
        claims.put("exp", NOW - LogoutTokenValidator.CLOCK_SKEW_SECONDS - 1);

        assertRefused(rs256(claims), "exp");
        claims.remove("exp");
        assertRefused(rs256(claims), "no exp");
        claims.put("exp", "tomorrow");
        assertRefused(rs256(claims), "exp is text");
    }

    @Test
    public void test_aTokenIssuedInTheFutureIsRefused() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.put("iat", NOW + LogoutTokenValidator.CLOCK_SKEW_SECONDS + 1);
        claims.put("exp", NOW + 1000);

        assertRefused(rs256(claims), "iat in the future");
        claims.remove("iat");
        assertRefused(rs256(claims), "no iat");
    }

    @Test
    public void test_aTokenThatIsTooOldIsRefusedEvenIfItsExpIsFarAway() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.put("iat", NOW - LogoutTokenValidator.MAX_AGE_SECONDS - LogoutTokenValidator.CLOCK_SKEW_SECONDS - 1);
        claims.put("exp", NOW + 10L * 365 * 24 * 3600);

        assertRefused(rs256(claims), "old iat");
    }

    @Test
    public void test_aTokenWithANonceIsRefused() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.put("nonce", "n-0S6_WzA2Mj");

        assertRefused(rs256(claims), "nonce");
    }

    @Test
    public void test_aTokenWithoutTheLogoutEventIsRefused() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.remove("events");
        assertRefused(rs256(claims), "no events");
        claims.put("events", Map.of("http://schemas.openid.net/event/other", Map.of()));
        assertRefused(rs256(claims), "another event");
        claims.put("events", Map.of(TestJwt.EVENT, "yes"));
        assertRefused(rs256(claims), "event that is not an object");
        claims.put("events", List.of(TestJwt.EVENT));
        assertRefused(rs256(claims), "events that is not an object");
    }

    @Test
    public void test_aTokenWithoutJtiIsRefused() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.remove("jti");
        assertRefused(rs256(claims), "no jti");
        claims.put("jti", 7);
        assertRefused(rs256(claims), "jti is a number");
    }

    @Test
    public void test_aTokenWithNeitherSidNorSubIsRefused() {
        final Map<String, Object> claims = TestJwt.logoutClaims(NOW);
        claims.remove("sid");
        claims.remove("sub");
        assertRefused(rs256(claims), "neither");
        claims.put("sid", "");
        claims.put("sub", 12);
        assertRefused(rs256(claims), "empty sid and sub that is a number");
    }

    @Test
    public void test_withoutAnIssuerOrClientIdNothingIsAccepted() {
        final String token = rs256(TestJwt.logoutClaims(NOW));
        assertThrows(LogoutTokenException.class, () -> validator.validate(token, "", TestJwt.CLIENT_ID, NOW));
        assertThrows(LogoutTokenException.class, () -> validator.validate(token, TestJwt.ISSUER, " ", NOW));
    }

    @Test
    public void test_theKeysAreFetchedOnceForSeveralTokens() {
        validate(rs256(TestJwt.logoutClaims(NOW)));
        validate(rs256(TestJwt.logoutClaims(NOW)));
        validate(TestJwt.es256(EC.getPrivate(), "ec-1", TestJwt.logoutClaims(NOW)));

        assertEquals(1, fetches.get());
    }
}
