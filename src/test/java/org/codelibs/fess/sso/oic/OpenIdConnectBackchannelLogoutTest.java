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
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.codelibs.core.io.FileUtil;
import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.sso.SsoResponseType;
import org.codelibs.fess.sso.oic.OpenIdConnectCredential.OpenIdUser;
import org.codelibs.fess.unit.LogCapturingAppender;
import org.codelibs.fess.unit.UnitFessTestCase;
import org.codelibs.fess.util.ComponentUtil;
import org.codelibs.fess.util.LogUtil;
import org.dbflute.utflute.mocklet.MockletHttpServletRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.lastaflute.web.response.ActionResponse;

/**
 * Tests OpenID Connect Back-Channel Logout 1.0 as the authenticator offers it: the endpoint that receives the logout
 * token, and the end of the sessions it names. The provider is a key pair of the test, and the index that the nodes
 * share is a map that the nodes of the test share.
 */
public class OpenIdConnectBackchannelLogoutTest extends UnitFessTestCase {

    private static final KeyPair KEY = TestJwt.rsaKey();

    private static final String KID = "key-1";

    private static final long START = 1_800_000_000_000L;

    /** The index, which every node of a test sees. */
    private final MemoryStore store = new MemoryStore();

    private final AtomicLong clock = new AtomicLong(START);

    private final AtomicInteger jwksFetches = new AtomicInteger();

    private String jwksUri = "https://idp.example.com/jwks";

    private String issuer = TestJwt.ISSUER;

    @Override
    protected void setUp(final TestInfo testInfo) throws Exception {
        super.setUp(testInfo);
        final File propFile = File.createTempFile("oic_bcl_test", ".properties");
        propFile.deleteOnExit();
        FileUtil.writeBytes(propFile.getAbsolutePath(), "".getBytes("UTF-8"));
        ComponentUtil.register(new DynamicProperties(propFile), "systemProperties");
        LogUtil.resetWarnOnce();
    }

    /** One node: its own memory, and the index that all nodes share. */
    private Node node() {
        return new Node();
    }

    private class Node extends OpenIdConnectAuthenticator {

        Node() {
            revocationStore = store;
        }

        @Override
        protected String getOicJwksUri() {
            return jwksUri;
        }

        @Override
        protected String getOicIssuer() {
            return issuer;
        }

        @Override
        protected String getOicClientId() {
            return TestJwt.CLIENT_ID;
        }

        @Override
        protected long currentTimeMillis() {
            return clock.get();
        }

        @Override
        protected String fetchJwks(final String url) {
            jwksFetches.incrementAndGet();
            return TestJwt.jwks(TestJwt.rsaJwk((RSAPublicKey) KEY.getPublic(), KID));
        }

        /** Receives a request: the answer is the status, which is null for a request this authenticator leaves alone. */
        ActionResponse receive(final String method, final String token) {
            final MockletHttpServletRequest request = getMockRequest();
            request.setMethod(method);
            if (token != null) {
                request.setParameter("logout_token", token);
            }
            return getResponse(SsoResponseType.LOGOUT);
        }
    }

    /** The in-memory index. */
    private static class MemoryStore extends LogoutRevocationStore {

        final Map<String, Long> revocations = new HashMap<>();

        final Set<String> usedTokens = new HashSet<>();

        final AtomicInteger lookups = new AtomicInteger();

        boolean failing;

        @Override
        public boolean markTokenUsed(final String key, final long now) {
            check();
            return usedTokens.add(key);
        }

        @Override
        public void forgetToken(final String key) {
            usedTokens.remove(key);
        }

        @Override
        public void revoke(final String key, final long now) {
            check();
            revocations.put(key, now);
        }

        @Override
        public long findRevokedAt(final String key, final long now) {
            lookups.incrementAndGet();
            check();
            return revocations.getOrDefault(key, -1L);
        }

        private void check() {
            if (failing) {
                throw new IllegalStateException("the index is down");
            }
        }
    }

    private String logoutToken(final String sid, final String sub) {
        final Map<String, Object> claims = TestJwt.logoutClaims(clock.get() / 1000);
        claims.remove("sid");
        claims.remove("sub");
        if (sid != null) {
            claims.put("sid", sid);
        }
        if (sub != null) {
            claims.put("sub", sub);
        }
        return TestJwt.rs256(KEY.getPrivate(), KID, claims);
    }

    private OpenIdUser login(final String sid, final String sub, final long loginTime) {
        return new OpenIdUser("taro@example.com", new String[] { "dev" }, new String[0], issuer, sub, sid, loginTime);
    }

    private static int status(final ActionResponse response) {
        return response.getHttpStatus().get();
    }

    private static String cacheControl(final ActionResponse response) {
        return response.getHeaderMap().get("Cache-Control")[0];
    }

    // ===================================================================================
    //                                                                      The endpoint
    //                                                                      ============
    @Test
    public void test_aValidLogoutTokenIsAnswered200WithNoStore() {
        final ActionResponse response = node().receive("POST", logoutToken("sid-1", "user-1"));

        assertEquals(200, status(response));
        assertEquals("no-store", cacheControl(response));
    }

    @Test
    public void test_aRefusedLogoutTokenIsAnswered400WithNoStore() {
        for (final String token : new String[] { "garbage", logoutToken(null, null), "" }) {
            final ActionResponse response = node().receive("POST", token);

            Assertions.assertEquals(400, status(response), token);
            Assertions.assertEquals("no-store", cacheControl(response), token);
        }
        assertTrue(store.revocations.isEmpty());
    }

    @Test
    public void test_aRequestThatIsNotALogoutTokenPostKeepsItsOldAnswer() {
        final Node node = node();
        // the endpoint answered 400 before there was back-channel logout, and still does
        Assertions.assertNull(node.receive("POST", null), "a POST without a token");
        Assertions.assertNull(node.receive("GET", logoutToken("sid-1", "user-1")),
                "a GET, which would put the token in the log of a proxy");
        assertNull(node.getResponse(SsoResponseType.METADATA));
        assertTrue(store.revocations.isEmpty());
    }

    @Test
    public void test_withoutAJwksUriTheEndpointIsOffAndRefusesEverything() {
        jwksUri = "";

        final ActionResponse response = node().receive("POST", logoutToken("sid-1", "user-1"));

        assertEquals(400, status(response));
        assertEquals("no-store", cacheControl(response));
        assertTrue(store.revocations.isEmpty());
        assertEquals(0, jwksFetches.get());
    }

    @Test
    public void test_withoutAnIssuerTheEndpointRefusesEverything() {
        issuer = "";

        assertEquals(400, status(node().receive("POST", logoutToken("sid-1", "user-1"))));
        assertTrue(store.revocations.isEmpty());
    }

    @Test
    public void test_aTokenThatWasUsedBeforeIsRefusedOnAnyNode() {
        final String token = logoutToken("sid-1", "user-1");

        assertEquals(200, status(node().receive("POST", token)));
        Assertions.assertEquals(400, status(node().receive("POST", token)), "replayed on another node");
        Assertions.assertEquals(400, status(node().receive("POST", token)), "replayed on a third");
        assertEquals(1, store.revocations.size());
    }

    @Test
    public void test_aTokenThatCouldNotBeRecordedCanBeSentAgain() {
        final String token = logoutToken("sid-1", "user-1");
        final Node node = node();

        store.failing = true;
        assertEquals(400, status(node.receive("POST", token)));
        store.failing = false;
        Assertions.assertEquals(200, status(node.receive("POST", token)), "the provider sends it again");
        assertEquals(1, store.revocations.size());
    }

    @Test
    public void test_nothingOfTheTokenIsLogged() {
        final String good = logoutToken("SESSION-MARKER", "SUBJECT-MARKER");
        final Map<String, Object> claims = TestJwt.logoutClaims(clock.get() / 1000);
        claims.put("sid", "OTHER-SESSION-MARKER");
        claims.put("nonce", "n");
        final String bad = TestJwt.rs256(KEY.getPrivate(), KID, claims);
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            node().receive("POST", good);
            node().receive("POST", good);
            node().receive("POST", bad);
        } finally {
            appender.detach();
        }
        final List<String> lines = new ArrayList<>();
        for (final LogEvent event : appender.events()) {
            lines.add(event.getMessage().getFormattedMessage());
        }
        assertFalse(lines.isEmpty());
        for (final String line : lines) {
            for (final String secret : new String[] { good, bad, "SESSION-MARKER", "SUBJECT-MARKER" }) {
                assertFalse(line.contains(secret), line);
            }
        }
        Assertions.assertEquals(2, appender.warnings().size(), "the replay and the nonce");
    }

    // ===================================================================================
    //                                                                    Ending sessions
    //                                                                    ===============
    @Test
    public void test_aSessionIsEndedBySid() {
        final Node node = node();
        final OpenIdUser user = login("sid-1", "user-1", clock.get());
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);
        assertFalse(user.isExpired());

        node.receive("POST", logoutToken("sid-1", "user-1"));

        assertTrue(user.isExpired());
    }

    @Test
    public void test_theOtherSessionsOfTheSameUserAreKeptWhenASidIsGiven() {
        final Node node = node();
        final OpenIdUser first = login("sid-1", "user-1", clock.get());
        final OpenIdUser second = login("sid-2", "user-1", clock.get());
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);

        node.receive("POST", logoutToken("sid-1", "user-1"));

        assertTrue(first.isExpired());
        assertFalse(second.isExpired());
    }

    @Test
    public void test_aSubjectLogoutEndsEverySessionOfTheUserOpenedBeforeIt() {
        final Node node = node();
        final OpenIdUser older = login("sid-1", "user-1", clock.get() - 5000);
        final OpenIdUser withoutSid = login(null, "user-1", clock.get() - 1000);
        final OpenIdUser another = login("sid-3", "user-2", clock.get() - 1000);
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);

        clock.addAndGet(2000);
        node.receive("POST", logoutToken(null, "user-1"));
        // the user logs in again, and is not ended by the logout that came before
        final OpenIdUser later = login("sid-4", "user-1", clock.addAndGet(1000));

        assertTrue(older.isExpired());
        assertTrue(withoutSid.isExpired());
        assertFalse(another.isExpired(), "another user");
        assertFalse(later.isExpired(), "a login after the logout");
    }

    @Test
    public void test_aLoginThatIsNotOfTheIssuerOrHasNoIdentifierIsNeverEnded() {
        final Node node = node();
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);
        node.receive("POST", logoutToken("sid-1", "user-1"));

        final OpenIdUser otherIssuer =
                new OpenIdUser("a@example.com", new String[0], new String[0], "https://other.example.com", "user-1", "sid-1", clock.get());
        final OpenIdUser noIdentifiers = new OpenIdUser("a@example.com", new String[0], new String[0]);
        final OpenIdUser noIssuer = new OpenIdUser("a@example.com", new String[0], new String[0], null, "user-1", "sid-1", clock.get());

        assertFalse(otherIssuer.isExpired());
        assertFalse(noIdentifiers.isExpired());
        assertFalse(noIssuer.isExpired());
    }

    @Test
    public void test_anotherNodeEndsTheSessionWithinTheCheckInterval() {
        final Node receiving = node();
        final Node serving = node();
        final OpenIdUser user = login("sid-1", "user-1", clock.get());
        ComponentUtil.register(serving, OpenIdConnectAuthenticator.COMPONENT_NAME);
        assertFalse(user.isExpired(), "the serving node looked, and found nothing");
        final int lookups = store.lookups.get();

        clock.addAndGet(5000);
        receiving.receive("POST", logoutToken("sid-1", "user-1"));
        // the request of the user, before the serving node looks again: its memory has the earlier answer
        assertFalse(user.isExpired());
        Assertions.assertEquals(lookups, store.lookups.get(), "no lookup for each request");

        clock.addAndGet(OpenIdConnectAuthenticator.REVOCATION_CHECK_MILLIS);

        assertTrue(user.isExpired());
    }

    @Test
    public void test_theReceivingNodeEndsTheSessionAtOnce() {
        final Node node = node();
        final OpenIdUser user = login("sid-1", "user-1", clock.get());
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);
        assertFalse(user.isExpired());

        node.receive("POST", logoutToken("sid-1", "user-1"));

        assertTrue(user.isExpired(), "without waiting for the interval");
    }

    @Test
    public void test_aSecondSubjectLogoutEndsTheSessionOpenedAfterTheFirst() {
        final Node node = node();
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);
        node.receive("POST", logoutToken(null, "user-1"));
        final OpenIdUser later = login("sid-9", "user-1", clock.addAndGet(1000));
        assertFalse(later.isExpired());

        clock.addAndGet(OpenIdConnectAuthenticator.REVOCATION_CHECK_MILLIS);
        node.receive("POST", logoutToken(null, "user-1"));

        assertTrue(later.isExpired());
    }

    @Test
    public void test_withoutAJwksUriNoSessionIsEndedAndTheIndexIsNotAsked() {
        final Node node = node();
        final OpenIdUser user = login("sid-1", "user-1", clock.get());
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);
        store.revocations.put(LogoutRevocationStore.sessionKey(issuer, "sid-1"), clock.get());
        jwksUri = "";

        assertFalse(user.isExpired());
        assertEquals(0, store.lookups.get());
    }

    @Test
    public void test_aFailingIndexEndsNothingAndIsNotAskedByEveryRequest() {
        final Node node = node();
        final OpenIdUser user = login("sid-1", "user-1", clock.get());
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);
        store.failing = true;

        for (int i = 0; i < 10; i++) {
            assertFalse(user.isExpired());
        }
        // the sid and the subject, once each
        assertEquals(2, store.lookups.get());
    }

    @Test
    public void test_anIndexThatFailsAfterAnAnswerKeepsThatAnswer() {
        final Node node = node();
        final OpenIdUser ended = login("sid-1", "user-1", clock.get());
        final OpenIdUser kept = login("sid-2", "user-2", clock.get());
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);
        node.receive("POST", logoutToken("sid-1", null));
        assertTrue(ended.isExpired());
        assertFalse(kept.isExpired());

        store.failing = true;
        clock.addAndGet(OpenIdConnectAuthenticator.REVOCATION_CHECK_MILLIS);

        // the lookups fail: no exception reaches the request, the session that was not ended is not ended, and the one that
        // was ended stays ended
        assertTrue(ended.isExpired());
        assertFalse(kept.isExpired());
    }

    @Test
    public void test_anIndexThatFailsWarnsOnceAndNeverThrows() {
        final Node node = node();
        ComponentUtil.register(node, OpenIdConnectAuthenticator.COMPONENT_NAME);
        store.failing = true;
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            for (int i = 0; i < 20; i++) {
                assertFalse(login("sid-" + i, "user-" + i, clock.get()).isExpired());
            }
        } finally {
            appender.detach();
        }
        Assertions.assertEquals(1, appender.warnings().size());
    }

    @Test
    public void test_aRefusalIsWarnedOncePerKind() {
        final String garbage = "a.b.c";
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            for (int i = 0; i < 10; i++) {
                Assertions.assertEquals(400, status(node().receive("POST", garbage)));
            }
            Assertions.assertEquals(1, appender.warnings().size(), "the same refusal");
            Assertions.assertEquals(400, status(node().receive("POST", logoutToken(null, null))));
            Assertions.assertEquals(2, appender.warnings().size(), "another kind of refusal");
        } finally {
            appender.detach();
        }
    }

    @Test
    public void test_withoutAJwksUriTheRefusalIsWarnedOncePerJvm() {
        jwksUri = "";
        final LogCapturingAppender appender = LogCapturingAppender.attach(OpenIdConnectAuthenticator.class.getName(), Level.DEBUG);
        try {
            for (int i = 0; i < 10; i++) {
                final ActionResponse response = node().receive("POST", logoutToken("sid-1", "user-1"));
                Assertions.assertEquals(400, status(response));
                Assertions.assertEquals("no-store", cacheControl(response));
            }
        } finally {
            appender.detach();
        }
        Assertions.assertEquals(1, appender.warnings().size());
    }

    @Test
    public void test_aLoginOfAnotherAuthenticatorSetupIsNotEndedWhenTheAuthenticatorIsNotThere() {
        // a user restored where the authenticator component is gone: nothing to ask, nothing ended
        final OpenIdUser user = login("sid-1", "user-1", clock.get());

        assertFalse(user.isExpired());
    }
}
