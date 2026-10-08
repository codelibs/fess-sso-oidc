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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.codelibs.core.io.FileUtil;
import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.app.web.base.login.ActionResponseCredential;
import org.codelibs.fess.unit.LogCapturingAppender;
import org.codelibs.fess.unit.UnitFessTestCase;
import org.codelibs.fess.util.ComponentUtil;
import org.dbflute.utflute.mocklet.MockletHttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.lastaflute.web.login.credential.LoginCredential;

import com.google.api.client.auth.oauth2.TokenResponse;
import com.sun.net.httpserver.HttpServer;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Unit tests for {@link OpenIdConnectAuthenticator}.
 * Tests JWT parsing, Base64 decoding, and configuration handling.
 */
public class OpenIdConnectAuthenticatorTest extends UnitFessTestCase {

    private OpenIdConnectAuthenticator authenticator;
    private DynamicProperties systemProperties;

    @Override
    protected void setUp(TestInfo testInfo) throws Exception {
        super.setUp(testInfo);
        authenticator = new OpenIdConnectAuthenticator();
        final File propFile = File.createTempFile("oic_test", ".properties");
        propFile.deleteOnExit();
        FileUtil.writeBytes(propFile.getAbsolutePath(), "".getBytes("UTF-8"));
        systemProperties = new DynamicProperties(propFile);
        ComponentUtil.register(systemProperties, "systemProperties");
    }

    @Test
    public void test_decodeBase64_null() {
        assertNull(authenticator.decodeBase64(null));
    }

    @Test
    public void test_decodeBase64_standard() {
        // "Hello" encoded in standard Base64
        final byte[] result = authenticator.decodeBase64("SGVsbG8=");
        assertEquals("Hello", new String(result));
    }

    @Test
    public void test_decodeBase64_urlSafe() {
        // Base64 URL encoding (uses - and _ instead of + and /)
        final byte[] result = authenticator.decodeBase64("SGVsbG9Xb3JsZA");
        assertEquals("HelloWorld", new String(result));
    }

    @Test
    public void test_decodeBase64_withPadding() {
        // Standard Base64 with padding
        final byte[] result = authenticator.decodeBase64("dGVzdA==");
        assertEquals("test", new String(result));
    }

    @Test
    public void test_parseJwtClaim_simpleValues() throws IOException {
        final String jwtClaim = "{\"sub\":\"user123\",\"name\":\"John Doe\",\"email\":\"john@example.com\"}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertEquals("user123", attributes.get("sub"));
        assertEquals("John Doe", attributes.get("name"));
        assertEquals("john@example.com", attributes.get("email"));
    }

    @Test
    public void test_parseJwtClaim_numericValues() throws IOException {
        final String jwtClaim = "{\"iat\":1609459200,\"exp\":1609462800,\"nbf\":1609459200}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertEquals(1609459200L, attributes.get("iat"));
        assertEquals(1609462800L, attributes.get("exp"));
        assertEquals(1609459200L, attributes.get("nbf"));
    }

    @Test
    public void test_parseJwtClaim_booleanValues() throws IOException {
        final String jwtClaim = "{\"email_verified\":true,\"active\":false}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertEquals(true, attributes.get("email_verified"));
        assertEquals(false, attributes.get("active"));
    }

    @Test
    public void test_parseJwtClaim_nullValue() throws IOException {
        final String jwtClaim = "{\"optional_claim\":null}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertTrue(attributes.containsKey("optional_claim"));
        assertNull(attributes.get("optional_claim"));
    }

    @Test
    public void test_parseJwtClaim_arrayValues() throws IOException {
        final String jwtClaim = "{\"roles\":[\"admin\",\"user\"],\"groups\":[\"group1\",\"group2\"]}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertTrue(attributes.get("roles") instanceof List);
        @SuppressWarnings("unchecked")
        final List<Object> roles = (List<Object>) attributes.get("roles");
        assertEquals(2, roles.size());
        assertEquals("admin", roles.get(0));
        assertEquals("user", roles.get(1));
    }

    @Test
    public void test_parseJwtClaim_nestedObject() throws IOException {
        final String jwtClaim = "{\"address\":{\"street\":\"123 Main St\",\"city\":\"Springfield\"}}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertTrue(attributes.get("address") instanceof Map);
        @SuppressWarnings("unchecked")
        final Map<String, Object> address = (Map<String, Object>) attributes.get("address");
        assertEquals("123 Main St", address.get("street"));
        assertEquals("Springfield", address.get("city"));
    }

    @Test
    public void test_parseJwtClaim_floatValue() throws IOException {
        final String jwtClaim = "{\"score\":95.5}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertEquals(95.5, attributes.get("score"));
    }

    @Test
    public void test_parseJwtClaim_emptyObject() throws IOException {
        final String jwtClaim = "{}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertTrue(attributes.isEmpty());
    }

    @Test
    public void test_parseJwtClaim_complexStructure() throws IOException {
        final String jwtClaim = "{\"user\":{\"id\":123,\"roles\":[\"admin\",\"user\"],\"permissions\":{\"read\":true,\"write\":false}}}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertTrue(attributes.containsKey("user"));
        @SuppressWarnings("unchecked")
        final Map<String, Object> user = (Map<String, Object>) attributes.get("user");
        assertEquals(123L, user.get("id"));

        @SuppressWarnings("unchecked")
        final List<Object> userRoles = (List<Object>) user.get("roles");
        assertEquals(2, userRoles.size());

        @SuppressWarnings("unchecked")
        final Map<String, Object> permissions = (Map<String, Object>) user.get("permissions");
        assertEquals(true, permissions.get("read"));
        assertEquals(false, permissions.get("write"));
    }

    @Test
    public void test_getOicAuthServerUrl_default() {
        final String url = authenticator.getOicAuthServerUrl();
        assertEquals("https://accounts.google.com/o/oauth2/auth", url);
    }

    @Test
    public void test_getOicTokenServerUrl_default() {
        final String url = authenticator.getOicTokenServerUrl();
        assertEquals("https://accounts.google.com/o/oauth2/token", url);
    }

    @Test
    public void test_getOicClientId_default() {
        final String clientId = authenticator.getOicClientId();
        assertEquals("", clientId);
    }

    @Test
    public void test_getOicClientSecret_default() {
        final String secret = authenticator.getOicClientSecret();
        assertEquals("", secret);
    }

    @Test
    public void test_getOicScope_default() {
        final String scope = authenticator.getOicScope();
        assertEquals("", scope);
    }

    @Test
    public void test_buildDefaultRedirectUrl_noBaseUrl() {
        final String url = authenticator.buildDefaultRedirectUrl();
        assertEquals("http://localhost:8080/sso/", url);
    }

    @Test
    public void test_logout_returnsNull() {
        assertNull(authenticator.logout(null));
    }

    @Test
    public void test_getResponse_returnsNull() {
        assertNull(authenticator.getResponse(null));
    }

    @Test
    public void test_getLoginCredential_withRequest() {
        // With a request context, should return ActionResponseCredential for OAuth redirect
        final var credential = authenticator.getLoginCredential();
        assertNotNull(credential);
        assertTrue(credential instanceof ActionResponseCredential);
    }

    @Test
    public void test_getAuthUrl_issuesAnUnguessableState() {
        // The state is the only thing standing between a login and a forged callback
        // (RFC 6749 section 10.12), and org.codelibs.core.net.UuidUtil -- which getAuthUrl used
        // to call -- is hex(localIP) + hex(identityHashCode(RANDOM)) +
        // hex((int) (currentTimeMillis() >> 32)) + hex(SecureRandom.nextInt()): the first 16 hex
        // characters never change within a JVM and the timestamp word moves every ~49.7 days, so
        // under 32 bits actually varied per call.
        final Set<String> states = new HashSet<>();
        final Set<String> prefixes = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            final HttpServletRequest request = getMockRequest();
            authenticator.getAuthUrl(request);
            // getAuthUrl stashes the same value it puts in the URL, and getLoginCredential only
            // ever compares the two with equals(), so nothing depends on its length or format.
            final String state = (String) request.getSession().getAttribute(OpenIdConnectAuthenticator.OIC_STATE);
            assertNotNull(state, "no state was stored in the session");
            states.add(state);
            prefixes.add(state.replace("-", "").substring(0, 16));
        }

        assertEquals(200, states.size());
        // The whole point: a fixed leading half is what UuidUtil produced.
        assertTrue("distinct prefixes: " + prefixes.size(), prefixes.size() > 190);
    }

    @Test
    public void test_parseJwtClaim_nestedArray() throws IOException {
        final String jwtClaim = "{\"matrix\":[[1,2],[3,4]]}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertTrue(attributes.get("matrix") instanceof List);
        @SuppressWarnings("unchecked")
        final List<Object> matrix = (List<Object>) attributes.get("matrix");
        assertEquals(2, matrix.size());

        @SuppressWarnings("unchecked")
        final List<Object> row1 = (List<Object>) matrix.get(0);
        assertEquals(1L, row1.get(0));
        assertEquals(2L, row1.get(1));
    }

    @Test
    public void test_parseJwtClaim_mixedArray() throws IOException {
        final String jwtClaim = "{\"mixed\":[\"string\",123,true,null]}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        @SuppressWarnings("unchecked")
        final List<Object> mixed = (List<Object>) attributes.get("mixed");
        assertEquals(4, mixed.size());
        assertEquals("string", mixed.get(0));
        assertEquals(123L, mixed.get(1));
        assertEquals(true, mixed.get(2));
        assertNull(mixed.get(3));
    }

    @Test
    public void test_parseJwtClaim_standardOidcClaims() throws IOException {
        final String jwtClaim = "{" + "\"iss\":\"https://issuer.example.com\"," + "\"sub\":\"user@example.com\","
                + "\"aud\":\"client-123\"," + "\"exp\":1700000000," + "\"iat\":1699999900," + "\"nonce\":\"abc123\","
                + "\"at_hash\":\"hashvalue\"," + "\"c_hash\":\"codehash\"" + "}";
        final Map<String, Object> attributes = new HashMap<>();

        authenticator.parseJwtClaim(jwtClaim, attributes);

        assertEquals("https://issuer.example.com", attributes.get("iss"));
        assertEquals("user@example.com", attributes.get("sub"));
        assertEquals("client-123", attributes.get("aud"));
        assertEquals(1700000000L, attributes.get("exp"));
        assertEquals(1699999900L, attributes.get("iat"));
        assertEquals("abc123", attributes.get("nonce"));
        assertEquals("hashvalue", attributes.get("at_hash"));
        assertEquals("codehash", attributes.get("c_hash"));
    }

    // ===================================================================================
    //                                                        Callback failure handling
    //                                                        =========================

    private static String segment(final String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    /** The client id every authenticator built by {@link #authenticatorReturning} is configured with. */
    private static final String CLIENT_ID = "test-client";

    /** 2100-01-01 in seconds since the epoch: a token that is not expired by the time anyone runs this. */
    private static final long FAR_FUTURE_EXP = 4102444800L;

    /** Builds a JWT without adding anything to the claim set: for tests of what a token that lacks a claim does. */
    private static String bareJwtOf(final String claimJson) {
        return segment("{\"alg\":\"RS256\"}") + "." + segment(claimJson) + "." + segment("signature");
    }

    /**
     * Builds a JWT whose claim set is valid for {@link #CLIENT_ID} unless the test says otherwise: {@code aud} and a
     * far-future {@code exp} are put in front of the given claims, and a key the test gives again wins because the
     * parser keeps the last value of a repeated key. Without them every token below would be refused for the missing
     * audience, and the tests of the email claim and of the debug log would pass without testing what they are named for.
     */
    private static String jwtOf(final String claimJson) {
        final String rest = claimJson.trim().substring(1).trim();
        final String defaults = "{\"aud\":\"" + CLIENT_ID + "\",\"exp\":" + FAR_FUTURE_EXP;
        return bareJwtOf(defaults + ("}".equals(rest) ? "}" : "," + rest));
    }

    private static TokenResponse tokenResponseWith(final Object idToken) {
        final TokenResponse tr = new TokenResponse();
        tr.setAccessToken("access-token");
        tr.setTokenType("Bearer");
        tr.setExpiresInSeconds(300L);
        if (idToken != null) {
            tr.set("id_token", idToken);
        }
        return tr;
    }

    private OpenIdConnectAuthenticator authenticatorReturning(final TokenResponse tr) {
        return authenticatorReturning(tr, "");
    }

    private OpenIdConnectAuthenticator authenticatorReturning(final TokenResponse tr, final String issuer) {
        return new OpenIdConnectAuthenticator() {
            @Override
            protected TokenResponse getTokenUrl(final String code) {
                return tr;
            }

            @Override
            protected String getOicClientId() {
                return CLIENT_ID;
            }

            @Override
            protected String getOicIssuer() {
                return issuer;
            }
        };
    }

    private LoginCredential callbackWith(final Object idToken) {
        return authenticatorReturning(tokenResponseWith(idToken)).processCallback(getMockRequest(), "the-code");
    }

    @Test
    public void test_processCallback_acceptsAWellFormedIdToken() {
        final LoginCredential credential = callbackWith(jwtOf("{\"email\":\"user@example.com\"}"));
        assertNotNull(credential);
        assertEquals("{user@example.com}", credential.toString());
    }

    @Test
    public void test_processCallback_withoutIdToken() {
        // A token response that carries no id_token used to reach ((String) null).split and throw.
        assertNull(callbackWith(null));
    }

    @Test
    public void test_processCallback_withNonStringIdToken() {
        assertNull(callbackWith(Long.valueOf(42)));
    }

    @Test
    public void test_processCallback_withBlankIdToken() {
        assertNull(callbackWith(""));
    }

    @Test
    public void test_processCallback_withTwoSegmentIdToken() {
        // jwt[2] used to throw ArrayIndexOutOfBoundsException, which no caller catches.
        assertNull(callbackWith("header.claim"));
    }

    @Test
    public void test_processCallback_withFourSegmentIdToken() {
        // A JWE compact serialisation has five segments and is not a signed JWT either.
        assertNull(callbackWith("a.b.c.d"));
    }

    @Test
    public void test_processCallback_withUndecodableSegment() {
        // decodeBase64 throws IllegalArgumentException, which only the IOException catch used to cover.
        assertNull(callbackWith("aGVhZGVy.!!!not-base64!!!.c2ln"));
    }

    @Test
    public void test_processCallback_withNonJsonClaim() {
        assertNull(callbackWith(segment("{\"alg\":\"RS256\"}") + "." + segment("not json at all") + "." + segment("s")));
    }

    @Test
    public void test_processCallback_withoutEmailClaim() {
        // The email claim is the user id. A credential without one logs in as a null-named user and
        // then fails on every later request, so it must not become a session at all.
        assertNull(callbackWith(jwtOf("{\"sub\":\"1234\",\"groups\":[\"dev\"]}")));
    }

    @Test
    public void test_processCallback_withBlankEmailClaim() {
        assertNull(callbackWith(jwtOf("{\"email\":\"\"}")));
    }

    @Test
    public void test_getLoginCredential_withProviderErrorResponse() {
        // error=access_denied with the state we issued means the provider refused this login. Starting
        // another authorization request would loop against a provider that keeps refusing, and would
        // override the user's own refusal against one that does not.
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(OpenIdConnectAuthenticator.OIC_STATE, "the-state");
        request.setParameter("state", "the-state");
        request.setParameter("error", "access_denied");
        request.setParameter("error_description", "The user declined");

        assertNull(authenticator.getLoginCredential());
        assertNull(request.getSession().getAttribute(OpenIdConnectAuthenticator.OIC_STATE));
    }

    @Test
    public void test_getLoginCredential_withErrorForAnotherState() {
        // A state that is not the one in the session is not this login's error response, so the
        // existing behaviour -- start a fresh authorization request -- is kept.
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(OpenIdConnectAuthenticator.OIC_STATE, "the-state");
        request.setParameter("state", "a-different-state");
        request.setParameter("error", "access_denied");

        final LoginCredential credential = authenticator.getLoginCredential();
        assertNotNull(credential);
        assertTrue(credential instanceof ActionResponseCredential);
    }

    @Test
    public void test_getLoginCredential_withoutCodeOrError() {
        // A bare callback with a matching state and neither parameter still restarts the flow.
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(OpenIdConnectAuthenticator.OIC_STATE, "the-state");
        request.setParameter("state", "the-state");

        final LoginCredential credential = authenticator.getLoginCredential();
        assertNotNull(credential);
        assertTrue(credential instanceof ActionResponseCredential);
    }

    // ===================================================================================
    //                                                        Caller-supplied values in the log
    //                                                        =================================

    private static final String FORGED_LINE = "2000-01-01 00:00:00,000 [forged] ERROR org.codelibs.fess.Forged";

    /** Returns every message this class logged while the callback below ran, one string per event. */
    private List<String> loggedWhileHandling(final String state, final String code, final String error, final String errorDescription) {
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(OpenIdConnectAuthenticator.OIC_STATE, "the-state");
        request.setParameter("state", state);
        if (code != null) {
            request.setParameter("code", code);
        }
        if (error != null) {
            request.setParameter("error", error);
        }
        if (errorDescription != null) {
            request.setParameter("error_description", errorDescription);
        }
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            authenticator.getLoginCredential();
        } finally {
            appender.detach();
        }
        final List<String> messages = new ArrayList<>();
        for (final LogEvent event : appender.events()) {
            messages.add(event.getMessage().getFormattedMessage());
        }
        return messages;
    }

    private void assertSingleLine(final List<String> messages) {
        for (final String message : messages) {
            assertFalse(message.matches("(?s).*[\\p{Cntrl}\\u0085\\u2028\\u2029].*"), "a line break reached the log: " + message);
        }
    }

    @Test
    public void test_getLoginCredential_providerErrorCannotStartALogLine() {
        // The callback is anonymous: anyone with a session of their own can send a state that matches it
        // together with an error, and the error text goes to the log at warn, which is on by default.
        final List<String> messages = loggedWhileHandling("the-state", null, "access_denied\n" + FORGED_LINE,
                "declined\r\n" + FORGED_LINE + "\u2028" + FORGED_LINE);

        assertSingleLine(messages);
        final String warn = String.join("\n", messages);
        assertTrue(warn.contains("error=access_denied?" + FORGED_LINE), "the error was not logged");
        assertTrue(warn.contains("error_description=declined??" + FORGED_LINE), "the error description was not logged");
    }

    @Test
    public void test_getLoginCredential_callbackCodeAndStateCannotStartALogLine() {
        final List<String> messages = loggedWhileHandling("the-state\n" + FORGED_LINE, "a-code\n" + FORGED_LINE, null, null);

        assertSingleLine(messages);
        assertTrue(String.join("\n", messages).contains("a-code?" + FORGED_LINE), "the code was not logged");
    }

    @Test
    public void test_getLoginCredential_longProviderErrorIsCut() {
        final List<String> messages = loggedWhileHandling("the-state", null, "access_denied", "x".repeat(10_000));

        final String warn = String.join("\n", messages);
        assertTrue(warn.length() < 1000, "a 10000 character error description was logged in full");
        assertTrue(warn.contains("x".repeat(OpenIdConnectAuthenticator.MAX_LOGGED_LENGTH) + "..."), "the cut is not marked");
    }

    @Test
    public void test_sanitizeForLog() {
        assertNull(OpenIdConnectAuthenticator.sanitizeForLog(null));
        assertEquals("", OpenIdConnectAuthenticator.sanitizeForLog(""));
        assertEquals("access_denied", OpenIdConnectAuthenticator.sanitizeForLog("access_denied"));
        assertEquals("a?b?c?d?e?f", OpenIdConnectAuthenticator.sanitizeForLog("a\nb\rc\u0085d\u2028e\u2029f"));
        assertEquals("\u65e5\u672c\u8a9e", OpenIdConnectAuthenticator.sanitizeForLog("\u65e5\u672c\u8a9e"));
    }

    // ===================================================================================
    //                                                            Debug log confidentiality
    //                                                            =========================

    private static String segment(final byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /**
     * Drives processCallback with a token response the test controls and returns everything this
     * class logged while doing it.
     */
    private String debugOutputOfCallback(final TokenResponse tr) {
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            authenticatorReturning(tr).processCallback(getMockRequest(), "the-code");
        } finally {
            appender.detach();
        }
        final StringBuilder buf = new StringBuilder();
        for (final LogEvent event : appender.events()) {
            buf.append(event.getMessage().getFormattedMessage()).append('\n');
        }
        return buf.toString();
    }

    private static TokenResponse secretCarryingTokenResponse() {
        final TokenResponse tr = new TokenResponse();
        tr.setAccessToken("ACCESS-TOKEN-MUST-NOT-BE-LOGGED");
        tr.setRefreshToken("REFRESH-TOKEN-MUST-NOT-BE-LOGGED");
        tr.setTokenType("Bearer");
        tr.setExpiresInSeconds(300L);
        // A signature is raw bytes; these are not valid UTF-8 text.
        final byte[] signature = { 0x00, 0x01, (byte) 0xC3, (byte) 0x28, (byte) 0xA0, (byte) 0xA1, 0x07 };
        // The claim set is valid for the client, so the whole callback runs and not only the part before the claim checks.
        final String claims = "{\"aud\":\"" + CLIENT_ID + "\",\"exp\":" + FAR_FUTURE_EXP + ",\"email\":\"user@example.com\"}";
        tr.set("id_token", segment("{\"alg\":\"RS256\"}") + "." + segment(claims) + "." + segment(signature));
        return tr;
    }

    @Test
    public void test_processCallback_doesNotLogTheAccessOrRefreshToken() {
        // The documentation tells administrators to raise this logger to debug when a login
        // misbehaves, so anything it prints reaches log files, issue reports and log collectors.
        final String output = debugOutputOfCallback(secretCarryingTokenResponse());

        assertFalse(output.contains("ACCESS-TOKEN-MUST-NOT-BE-LOGGED"), "the access token was logged");
        assertFalse(output.contains("REFRESH-TOKEN-MUST-NOT-BE-LOGGED"), "the refresh token was logged");
        // What is actually needed to diagnose a login is still there.
        assertTrue(output.contains("user@example.com"), "the claim set was not logged");
        assertTrue(output.contains("Bearer"), "the token type was not logged");
    }

    @Test
    public void test_processCallback_doesNotLogRawSignatureBytes() {
        final String output = debugOutputOfCallback(secretCarryingTokenResponse());

        // A single invalid byte in fess.log makes the whole file count as binary, and grep and the
        // rest of the usual log tooling then skip it without saying so.
        assertFalse(output.contains("\u0000"), "a NUL byte reached the log");
        assertFalse(output.contains("\u0007"), "a control byte reached the log");
        assertFalse(output.contains("\ufffd"), "an undecodable byte reached the log");
    }

    // ===================================================================================
    //                                                                   Claim validation
    //                                                                   ================

    private static final long NOW = 1_700_000_000L;

    private static final String ISSUER = "https://idp.example.com/realms/fess";

    private static OpenIdConnectAuthenticator validatorFor(final String clientId, final String issuer) {
        return new OpenIdConnectAuthenticator() {
            @Override
            protected String getOicClientId() {
                return clientId;
            }

            @Override
            protected String getOicIssuer() {
                return issuer;
            }
        };
    }

    /** The claims of a token that is acceptable for {@link #CLIENT_ID} at {@link #NOW}; a test changes the one it is about. */
    private static Map<String, Object> validClaims() {
        final Map<String, Object> claims = new HashMap<>();
        claims.put("aud", CLIENT_ID);
        claims.put("exp", NOW + 3600);
        return claims;
    }

    /** Runs the check with no issuer configured, which is the default. */
    private static void validate(final Map<String, Object> claims) {
        validatorFor(CLIENT_ID, "").validateIdTokenClaims(claims, NOW);
    }

    /** Returns the reason of the rejection, and fails if there was none or if it was not an IllegalArgumentException. */
    private static String rejectionOf(final OpenIdConnectAuthenticator authenticator, final Map<String, Object> claims) {
        return Assertions.assertThrows(IllegalArgumentException.class, () -> authenticator.validateIdTokenClaims(claims, NOW)).getMessage();
    }

    private static String rejectionOf(final Map<String, Object> claims) {
        return rejectionOf(validatorFor(CLIENT_ID, ""), claims);
    }

    @Test
    public void test_validateIdTokenClaims_audienceAsString() {
        validate(validClaims());
    }

    @Test
    public void test_validateIdTokenClaims_audienceAsArrayContainingTheClient() {
        final Map<String, Object> claims = validClaims();
        claims.put("aud", Arrays.asList("another-client", CLIENT_ID));
        claims.put("azp", CLIENT_ID);
        validate(claims);
    }

    @Test
    public void test_validateIdTokenClaims_missingAudience() {
        final Map<String, Object> claims = validClaims();
        claims.remove("aud");
        assertTrue(rejectionOf(claims).contains("not issued for this client"), "the reason names the audience");
    }

    @Test
    public void test_validateIdTokenClaims_emptyAudienceArray() {
        final Map<String, Object> claims = validClaims();
        claims.put("aud", new ArrayList<>());
        rejectionOf(claims);
    }

    @Test
    public void test_validateIdTokenClaims_audienceOfAnotherClient() {
        final Map<String, Object> claims = validClaims();
        claims.put("aud", "another-client");
        final String reason = rejectionOf(claims);
        assertTrue(reason.contains("aud=another-client"), "the reason prints the audience: " + reason);
        assertTrue(reason.contains("oic.client.id=" + CLIENT_ID), "the reason prints the expected client id: " + reason);
    }

    @Test
    public void test_validateIdTokenClaims_audienceArrayWithoutTheClient() {
        final Map<String, Object> claims = validClaims();
        claims.put("aud", Arrays.asList("a", "b"));
        claims.put("azp", "a");
        rejectionOf(claims);
    }

    @Test
    public void test_validateIdTokenClaims_audienceOfAnotherType() {
        // A claim set is whatever the provider sent: none of these may end in a ClassCastException.
        final List<Object> unusable = new ArrayList<>();
        unusable.add(42L);
        unusable.add(true);
        unusable.add(new HashMap<String, Object>());
        unusable.add(null);
        unusable.add(Arrays.asList(CLIENT_ID));
        for (final Object aud : Arrays.asList(Long.valueOf(42), Boolean.TRUE, new HashMap<String, Object>(), unusable)) {
            final Map<String, Object> claims = validClaims();
            claims.put("aud", aud);
            rejectionOf(claims);
        }
        final Map<String, Object> claims = validClaims();
        claims.put("aud", null);
        rejectionOf(claims);
    }

    @Test
    public void test_validateIdTokenClaims_blankClientIdRefusesEveryToken() {
        // Fail closed: an unset oic.client.id must not turn into "any audience will do".
        for (final String clientId : new String[] { "", "   " }) {
            final Map<String, Object> claims = validClaims();
            claims.put("aud", clientId);
            final String reason = rejectionOf(validatorFor(clientId, ""), claims);
            assertTrue(reason.contains("oic.client.id is not set"), "the reason names the setting: " + reason);
        }
    }

    @Test
    public void test_validateIdTokenClaims_severalAudiencesWithAzp() {
        final Map<String, Object> claims = validClaims();
        claims.put("aud", Arrays.asList(CLIENT_ID, "resource-server"));
        claims.put("azp", CLIENT_ID);
        validate(claims);
    }

    @Test
    public void test_validateIdTokenClaims_severalAudiencesWithoutAzp() {
        final Map<String, Object> claims = validClaims();
        claims.put("aud", Arrays.asList(CLIENT_ID, "resource-server"));
        final String reason = rejectionOf(claims);
        assertTrue(reason.contains("azp"), "the reason names azp: " + reason);
    }

    @Test
    public void test_validateIdTokenClaims_azpOfAnotherClient() {
        final Map<String, Object> claims = validClaims();
        claims.put("azp", "another-client");
        final String reason = rejectionOf(claims);
        assertTrue(reason.contains("azp=another-client"), "the reason prints azp: " + reason);
    }

    @Test
    public void test_validateIdTokenClaims_azpOfTheClientWithOneAudience() {
        final Map<String, Object> claims = validClaims();
        claims.put("azp", CLIENT_ID);
        validate(claims);
    }

    @Test
    public void test_validateIdTokenClaims_azpThatIsNotAString() {
        final Map<String, Object> claims = validClaims();
        claims.put("azp", Long.valueOf(7));
        rejectionOf(claims);
    }

    @Test
    public void test_validateIdTokenClaims_missingExpiry() {
        final Map<String, Object> claims = validClaims();
        claims.remove("exp");
        assertTrue(rejectionOf(claims).contains("exp"), "the reason names exp");
        claims.put("exp", null);
        rejectionOf(claims);
    }

    @Test
    public void test_validateIdTokenClaims_expiryThatIsNotANumber() {
        final Map<String, Object> claims = validClaims();
        claims.put("exp", "123");
        rejectionOf(claims);
        claims.put("exp", Boolean.TRUE);
        rejectionOf(claims);
        claims.put("exp", Arrays.asList(NOW + 3600));
        rejectionOf(claims);
    }

    @Test
    public void test_validateIdTokenClaims_expiredWithinTheClockSkew() {
        final Map<String, Object> claims = validClaims();
        claims.put("exp", NOW - (OpenIdConnectAuthenticator.CLOCK_SKEW_SECONDS - 1));
        validate(claims);
    }

    @Test
    public void test_validateIdTokenClaims_expiredAtTheEndOfTheClockSkew() {
        // The boundary is exclusive: now == exp + skew is already refused.
        final Map<String, Object> claims = validClaims();
        claims.put("exp", NOW - OpenIdConnectAuthenticator.CLOCK_SKEW_SECONDS);
        final String reason = rejectionOf(claims);
        assertTrue(reason.contains("exp=" + (NOW - 300)), "the reason prints exp: " + reason);
        assertTrue(reason.contains("now=" + NOW), "the reason prints the current time: " + reason);
        assertTrue(reason.contains("skew=300"), "the reason prints the skew: " + reason);
    }

    @Test
    public void test_validateIdTokenClaims_expiredBeyondTheClockSkew() {
        final Map<String, Object> claims = validClaims();
        claims.put("exp", NOW - (OpenIdConnectAuthenticator.CLOCK_SKEW_SECONDS + 1));
        rejectionOf(claims);
    }

    @Test
    public void test_validateIdTokenClaims_expiryAsDouble() {
        // The JSON parser answers a Double for a number written with a fraction or an exponent.
        final Map<String, Object> claims = validClaims();
        claims.put("exp", NOW + 3600.0);
        validate(claims);
        claims.put("exp", NOW - 301.0);
        rejectionOf(claims);
    }

    @Test
    public void test_validateIdTokenClaims_expiryOfLongMaxValue() {
        // Long.MAX_VALUE + skew wraps around in long arithmetic and would read as already expired.
        final Map<String, Object> claims = validClaims();
        claims.put("exp", Long.MAX_VALUE);
        validate(claims);
    }

    @Test
    public void test_validateIdTokenClaims_noIssuerConfigured() {
        // Without oic.issuer the claim is not checked: a token without one, or with any value, passes.
        validate(validClaims());
        final Map<String, Object> claims = validClaims();
        claims.put("iss", "https://anything.example.com");
        validate(claims);
        claims.put("iss", Long.valueOf(1));
        validate(claims);
    }

    @Test
    public void test_validateIdTokenClaims_issuerEqualToTheConfiguredOne() {
        final Map<String, Object> claims = validClaims();
        claims.put("iss", ISSUER);
        validatorFor(CLIENT_ID, ISSUER).validateIdTokenClaims(claims, NOW);
    }

    @Test
    public void test_validateIdTokenClaims_issuerOfAnotherProvider() {
        final Map<String, Object> claims = validClaims();
        claims.put("iss", "https://other.example.com");
        final String reason = rejectionOf(validatorFor(CLIENT_ID, ISSUER), claims);
        assertTrue(reason.contains("iss=https://other.example.com"), "the reason prints iss: " + reason);
        assertTrue(reason.contains("oic.issuer=" + ISSUER), "the reason prints the configured issuer: " + reason);
    }

    @Test
    public void test_validateIdTokenClaims_missingIssuerWhenConfigured() {
        rejectionOf(validatorFor(CLIENT_ID, ISSUER), validClaims());
    }

    @Test
    public void test_validateIdTokenClaims_issuerThatIsNotAString() {
        final Map<String, Object> claims = validClaims();
        claims.put("iss", Arrays.asList(ISSUER));
        rejectionOf(validatorFor(CLIENT_ID, ISSUER), claims);
    }

    @Test
    public void test_validateIdTokenClaims_issuerIsComparedExactly() {
        // No normalisation: the value is the issuer identifier and the provider's metadata says what it is.
        final Map<String, Object> claims = validClaims();
        claims.put("iss", ISSUER + "/");
        rejectionOf(validatorFor(CLIENT_ID, ISSUER), claims);
        claims.put("iss", ISSUER);
        rejectionOf(validatorFor(CLIENT_ID, ISSUER + "/"), claims);
        claims.put("iss", ISSUER.replace("https://", "http://"));
        rejectionOf(validatorFor(CLIENT_ID, ISSUER), claims);
        claims.put("iss", ISSUER.toUpperCase());
        rejectionOf(validatorFor(CLIENT_ID, ISSUER), claims);
    }

    @Test
    public void test_getOicIssuer() {
        assertEquals("", authenticator.getOicIssuer());
        // The component outlives this test, so the key is set on the one the code reads and removed again.
        final DynamicProperties properties = ComponentUtil.getSystemProperties();
        properties.setProperty(OpenIdConnectAuthenticator.OIC_ISSUER, "  " + ISSUER + " \t");
        try {
            assertEquals(ISSUER, authenticator.getOicIssuer());
        } finally {
            properties.remove(OpenIdConnectAuthenticator.OIC_ISSUER);
        }
        assertEquals("", authenticator.getOicIssuer());
    }

    @Test
    public void test_validateIdTokenClaims_missingIssuerSettingIsLoggedOncePerAuthenticator() {
        final OpenIdConnectAuthenticator first = validatorFor(CLIENT_ID, "");
        final OpenIdConnectAuthenticator second = validatorFor(CLIENT_ID, "");
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            first.validateIdTokenClaims(validClaims(), NOW);
            first.validateIdTokenClaims(validClaims(), NOW);
            assertEquals(1, appender.warnings().size(), "the second validation logged again");
            second.validateIdTokenClaims(validClaims(), NOW);
            assertEquals(2, appender.warnings().size(), "another authenticator is its own instance");
        } finally {
            appender.detach();
        }
        final String warning = appender.warnings().get(0);
        assertTrue(warning.contains("oic.issuer is not set"), "the setting is not named: " + warning);
        assertTrue(warning.contains("/.well-known/openid-configuration"), "the source of the value is not named: " + warning);
    }

    @Test
    public void test_validateIdTokenClaims_configuredIssuerLogsNothing() {
        final Map<String, Object> claims = validClaims();
        claims.put("iss", ISSUER);
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            validatorFor(CLIENT_ID, ISSUER).validateIdTokenClaims(claims, NOW);
        } finally {
            appender.detach();
        }
        assertTrue(appender.warnings().isEmpty(), "a warning was logged: " + appender.warnings());
    }

    // ===================================================================================
    //                                                          Token endpoint transport
    //                                                          ========================

    private static final String ENDPOINT_REFUSAL =
            "oic.token.server.url must be https (http is accepted only for localhost, 127.x.x.x and ::1)";

    private void assertAccepted(final String... urls) {
        for (final String url : urls) {
            try {
                authenticator.requireSecureTokenEndpoint(url);
            } catch (final IllegalArgumentException e) {
                fail(url + " was refused: " + e.getMessage());
            }
        }
    }

    private void assertRefused(final String... urls) {
        for (final String url : urls) {
            final IllegalArgumentException e =
                    Assertions.assertThrows(IllegalArgumentException.class, () -> authenticator.requireSecureTokenEndpoint(url), url);
            assertEquals(ENDPOINT_REFUSAL, e.getMessage());
        }
    }

    @Test
    public void test_requireSecureTokenEndpoint_https() {
        assertAccepted("https://idp.example.com/token", "HTTPS://IDP.EXAMPLE.COM/token", "https://idp.example.com:8443/realms/x/token",
                "https://accounts.google.com/o/oauth2/token");
    }

    @Test
    public void test_requireSecureTokenEndpoint_httpsWithAHostJavaCannotParseAsOne() {
        // java.net.URI reports no host for a name with an underscore, which is common for container service names.
        assertAccepted("https://idp_internal:8443/token");
    }

    @Test
    public void test_requireSecureTokenEndpoint_surroundingWhitespaceIsIgnored() {
        // As java.net.URL, which the request is built from, ignores it.
        assertAccepted(" https://idp.example.com/token\n", "\thttp://localhost:8180/token ");
    }

    @Test
    public void test_requireSecureTokenEndpoint_httpToAnotherHost() {
        assertRefused("http://example.com/token", "http://idp.example.com:8180/token", "HTTP://IDP.EXAMPLE.COM/token",
                "http://10.0.0.5/token", "http://0.0.0.0:8180/token", "http://192.168.1.10/token");
    }

    @Test
    public void test_requireSecureTokenEndpoint_httpToThisMachine() {
        assertAccepted("http://localhost/token", "http://localhost:8180/token", "http://LOCALHOST:8180/token", "http://127.0.0.1/token",
                "http://127.0.0.1:8180/realms/x/token", "http://127.1.2.3:8180/token", "http://[::1]/token", "http://[::1]:8180/token",
                "HTTP://localhost:8180/token");
    }

    @Test
    public void test_requireSecureTokenEndpoint_lookAlikesOfThisMachine() {
        // Only the literal host counts. Each of these names or ends up at another machine.
        assertRefused("http://localhost@evil.example.com", "http://localhost@evil.example.com/token",
                "http://localhost:8180@evil.example.com/token", "http://127.0.0.1@evil.example.com/token",
                "http://127.0.0.1.evil.example.com", "http://localhost.evil.example.com", "http://evil.example.com/localhost",
                "http://evil.example.com/?u=localhost", "http://evil.example.com#@localhost", "http://127.1", "http://127.0.1",
                "http://127.0.0.256", "http://127.0.0.01", "http://[::2]/token", "http://[::1].evil.example.com/token",
                "http://idp.localhost:8180/token", "http://localhost./token");
    }

    @Test
    public void test_requireSecureTokenEndpoint_notAnAbsoluteHttpUrl() {
        assertRefused(null, "", "   ", "/oauth2/token", "idp.example.com/token", "//idp.example.com/token", "ftp://idp.example.com/token",
                "ftp://localhost/token", "file:///etc/passwd", "javascript:alert(1)", "http://", "http:///token", "https:", "://x");
    }

    @Test
    public void test_requireSecureTokenEndpoint_malformedUrl() {
        assertRefused("http://exa mple.com/token", "https://idp.example.com/to ken", "http://localhost\\@evil.example.com",
                "https://[::1/token");
    }

    @Test
    public void test_requireSecureTokenEndpoint_refusalDoesNotRepeatTheUrl() {
        // The URL may carry a user name and password (https://user:secret@host/), and the message is logged.
        for (final String url : new String[] { "http://user:s3cr3t@idp.example.com/token", "ftp://user:s3cr3t@idp.example.com/token",
                "http://user:s3cr3t@idp.example.com/to ken", "user:s3cr3t@idp.example.com/token" }) {
            final IllegalArgumentException e =
                    Assertions.assertThrows(IllegalArgumentException.class, () -> authenticator.requireSecureTokenEndpoint(url));
            assertFalse(e.getMessage().contains("s3cr3t"), "the message repeats the URL: " + e.getMessage());
            assertFalse(e.getMessage().contains("idp.example.com"), "the message repeats the URL: " + e.getMessage());
            assertNull(e.getCause(), "a cause would carry the parser's message, which repeats the URL");
        }
    }

    private static OpenIdConnectAuthenticator authenticatorWithTokenEndpoint(final String url) {
        return new OpenIdConnectAuthenticator() {
            @Override
            protected String getOicTokenServerUrl() {
                return url;
            }

            @Override
            protected String getOicClientId() {
                return CLIENT_ID;
            }
        };
    }

    @Test
    public void test_getTokenUrl_refusesAPlainHttpEndpointBeforeAnyRequest() {
        // The refusal is an IllegalArgumentException. A request to the host would have ended as an IOException
        // (no such host, connection refused) or as a response, so this proves the check comes first.
        final OpenIdConnectAuthenticator remote = authenticatorWithTokenEndpoint("http://idp.invalid/token");
        Assertions.assertThrows(IllegalArgumentException.class, () -> remote.getTokenUrl("the-code"));
    }

    @Test
    public void test_processCallback_withAPlainHttpTokenEndpoint() {
        final OpenIdConnectAuthenticator remote = authenticatorWithTokenEndpoint("http://user:s3cr3t@idp.invalid/token");
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            assertNull(remote.processCallback(getMockRequest(), "the-code"));
        } finally {
            appender.detach();
        }
        final String warnings = String.join("\n", appender.warnings());
        assertTrue(warnings.contains("Failed to process the OpenID Connect callback: " + ENDPOINT_REFUSAL), "no warning: " + warnings);
        assertFalse(warnings.contains("s3cr3t"), "the URL was logged: " + warnings);
    }

    @Test
    public void test_processCallback_overPlainHttpToTheLoopbackAddress() throws IOException {
        // The accepted http endpoint is really reached: a token endpoint on 127.0.0.1, answering as a provider does.
        final String body = "{\"access_token\":\"access-token\",\"token_type\":\"Bearer\",\"expires_in\":300,\"id_token\":\""
                + jwtOf("{\"email\":\"user@example.com\"}") + "\"}";
        final HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0);
        server.createContext("/token", exchange -> {
            final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        try {
            final OpenIdConnectAuthenticator local =
                    authenticatorWithTokenEndpoint("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
            final LoginCredential credential = local.processCallback(getMockRequest(), "the-code");
            assertNotNull(credential);
            assertEquals("{user@example.com}", credential.toString());
        } finally {
            server.stop(0);
        }
    }

    // ===================================================================================
    //                                                    Claim validation in the callback
    //                                                    ================================

    private List<String> loggedByCallback(final OpenIdConnectAuthenticator authenticator, final LoginCredential[] result) {
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            result[0] = authenticator.processCallback(getMockRequest(), "the-code");
        } finally {
            appender.detach();
        }
        final List<String> messages = new ArrayList<>();
        for (final LogEvent event : appender.events()) {
            messages.add(event.getMessage().getFormattedMessage());
        }
        return messages;
    }

    @Test
    public void test_processCallback_acceptsATokenIssuedForTheClient() {
        // The positive control of the tests below: the same call with only the claim under test changed.
        final LoginCredential[] result = new LoginCredential[1];
        final List<String> messages = loggedByCallback(
                authenticatorReturning(tokenResponseWith(jwtOf("{\"email\":\"user@example.com\",\"iss\":\"" + ISSUER + "\"}")), ISSUER),
                result);
        assertNotNull(result[0]);
        assertEquals("{user@example.com}", result[0].toString());
        assertFalse(String.join("\n", messages).contains("Failed to process"), "a failure was logged: " + messages);
    }

    @Test
    public void test_processCallback_withTheAudienceOfAnotherClient() {
        final LoginCredential[] result = new LoginCredential[1];
        final List<String> messages = loggedByCallback(
                authenticatorReturning(tokenResponseWith(jwtOf("{\"email\":\"user@example.com\",\"aud\":\"another-client\"}"))), result);
        assertNull(result[0]);
        assertTrue(messages.contains("Failed to process the OpenID Connect callback: The ID token was not issued for this client:"
                + " aud=another-client, oic.client.id=test-client"), "the warning differs: " + messages);
    }

    @Test
    public void test_processCallback_withAnExpiredToken() {
        final LoginCredential[] result = new LoginCredential[1];
        final List<String> messages = loggedByCallback(
                authenticatorReturning(tokenResponseWith(jwtOf("{\"email\":\"user@example.com\",\"exp\":1700000000}"))), result);
        assertNull(result[0]);
        assertTrue(String.join("\n", messages).contains("The ID token has expired: exp=1700000000, now="),
                "the warning differs: " + messages);
    }

    @Test
    public void test_processCallback_withoutExpiry() {
        assertNull(callbackWith(bareJwtOf("{\"aud\":\"" + CLIENT_ID + "\",\"email\":\"user@example.com\"}")));
    }

    @Test
    public void test_processCallback_withoutAudience() {
        assertNull(callbackWith(bareJwtOf("{\"exp\":" + FAR_FUTURE_EXP + ",\"email\":\"user@example.com\"}")));
    }

    @Test
    public void test_processCallback_withAudienceOfAnotherType() {
        // The claim set comes from the provider: a number where a string is expected must end as a refusal.
        assertNull(callbackWith(jwtOf("{\"email\":\"user@example.com\",\"aud\":7}")));
        assertNull(callbackWith(jwtOf("{\"email\":\"user@example.com\",\"aud\":{\"a\":1}}")));
        assertNull(callbackWith(jwtOf("{\"email\":\"user@example.com\",\"exp\":\"soon\"}")));
        assertNull(callbackWith(jwtOf("{\"email\":\"user@example.com\",\"azp\":[\"" + CLIENT_ID + "\"]}")));
    }

    @Test
    public void test_processCallback_withoutAConfiguredClientId() {
        // authenticator itself reads oic.client.id from the (empty) system properties.
        final TokenResponse tr = tokenResponseWith(jwtOf("{\"email\":\"user@example.com\"}"));
        final OpenIdConnectAuthenticator unconfigured = new OpenIdConnectAuthenticator() {
            @Override
            protected TokenResponse getTokenUrl(final String code) {
                return tr;
            }
        };
        assertNull(unconfigured.processCallback(getMockRequest(), "the-code"));
    }

    @Test
    public void test_processCallback_withTheIssuerOfAnotherProvider() {
        final TokenResponse tr = tokenResponseWith(jwtOf("{\"email\":\"user@example.com\",\"iss\":\"https://other.example.com\"}"));
        assertNull(authenticatorReturning(tr, ISSUER).processCallback(getMockRequest(), "the-code"));
        // The same token is accepted while nothing is configured.
        assertNotNull(authenticatorReturning(tr, "").processCallback(getMockRequest(), "the-code"));
    }

    @Test
    public void test_processCallback_tokenValuesCannotStartALogLine() {
        // The token is data from outside: an iss, aud or azp with a line break must not start a line of its own.
        final String forged = "\\n" + FORGED_LINE;
        final String[][] claimSetAndLoggedValue = {
                { "{\"email\":\"user@example.com\",\"iss\":\"https://evil.example.com" + forged + "\"}",
                        "iss=https://evil.example.com?" + FORGED_LINE },
                { "{\"email\":\"user@example.com\",\"iss\":\"" + ISSUER + "\",\"aud\":\"evil" + forged + "\"}", "aud=evil?" + FORGED_LINE },
                { "{\"email\":\"user@example.com\",\"iss\":\"" + ISSUER + "\",\"azp\":\"evil" + forged + "\"}",
                        "azp=evil?" + FORGED_LINE } };
        for (final String[] pair : claimSetAndLoggedValue) {
            final LoginCredential[] result = new LoginCredential[1];
            final List<String> messages = loggedByCallback(authenticatorReturning(tokenResponseWith(jwtOf(pair[0])), ISSUER), result);
            assertNull(result[0]);
            assertSingleLine(messages);
            assertTrue(String.join("\n", messages).contains(pair[1]), "the value was not logged: " + messages);
        }
    }
}
