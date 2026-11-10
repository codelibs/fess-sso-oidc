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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.codelibs.core.io.FileUtil;
import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.app.web.base.login.ActionResponseCredential;
import org.codelibs.fess.helper.ActivityHelper;
import org.codelibs.fess.session.SessionDataSerializer;
import org.codelibs.fess.unit.UnitFessTestCase;
import org.codelibs.fess.util.ComponentUtil;
import org.dbflute.optional.OptionalThing;
import org.dbflute.utflute.mocklet.MockletHttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.lastaflute.web.login.credential.LoginCredential;

import com.google.api.client.auth.oauth2.TokenResponse;

import jakarta.servlet.http.HttpSession;

/**
 * Tests the login handshake across nodes: the authorization request is issued on one node and its callback
 * is answered on another, each with a serializer of its own and nothing but the stored bytes between them.
 */
public class OpenIdConnectSessionSharingTest extends UnitFessTestCase {

    private static final String CLIENT_ID = "test-client";

    private static final long FAR_FUTURE_EXP = 4102444800L;

    private int loginFailures;

    private final AtomicInteger tokenRequests = new AtomicInteger();

    @Override
    protected void setUp(final TestInfo testInfo) throws Exception {
        super.setUp(testInfo);
        final File propFile = File.createTempFile("oic_test", ".properties");
        propFile.deleteOnExit();
        FileUtil.writeBytes(propFile.getAbsolutePath(), "".getBytes("UTF-8"));
        ComponentUtil.register(new DynamicProperties(propFile), "systemProperties");
        ComponentUtil.register(new ActivityHelper() {
            @Override
            public void loginFailure(final OptionalThing<LoginCredential> credential) {
                loginFailures++;
            }
        }, "activityHelper");
    }

    /** The serializer of one node. */
    private static SessionDataSerializer node() {
        final SessionDataSerializer serializer = new SessionDataSerializer();
        serializer.register(OpenIdConnectCredential.OpenIdUser.class, new OpenIdUserSerializer());
        return serializer;
    }

    /** An authenticator that answers the token request with a token for the nonce it is given. */
    private OpenIdConnectAuthenticator authenticator(final String nonce) {
        final String claims =
                "{\"aud\":\"" + CLIENT_ID + "\",\"exp\":" + FAR_FUTURE_EXP + ",\"nonce\":\"" + nonce + "\",\"email\":\"taro@example.com\"}";
        final TokenResponse tr = new TokenResponse();
        tr.setAccessToken("access-token");
        tr.setTokenType("Bearer");
        tr.setExpiresInSeconds(300L);
        final java.util.function.Function<String, String> b64 =
                s -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        tr.set("id_token", b64.apply("{\"alg\":\"RS256\"}") + "." + b64.apply(claims) + "." + b64.apply("signature"));
        return new OpenIdConnectAuthenticator() {
            @Override
            protected TokenResponse getTokenUrl(final String code) {
                tokenRequests.incrementAndGet();
                return tr;
            }

            @Override
            protected String getOicClientId() {
                return CLIENT_ID;
            }

            @Override
            protected String getOicIssuer() {
                return "";
            }
        };
    }

    /** What the session store keeps of the session of the request: the bytes of its attributes. */
    private static byte[] store(final SessionDataSerializer node, final HttpSession session) {
        final Map<String, Object> attributes = new LinkedHashMap<>();
        for (final String name : Collections.list(session.getAttributeNames())) {
            attributes.put(name, session.getAttribute(name));
        }
        return node.toBytes(attributes);
    }

    /** A request on a node that has nothing but the stored bytes of the session. */
    private static MockletHttpServletRequest load(final SessionDataSerializer node, final byte[] stored,
            final MockletHttpServletRequest request) {
        final HttpSession session = request.getSession();
        for (final String name : Collections.list(session.getAttributeNames())) {
            session.removeAttribute(name);
        }
        node.fromBytes(stored).forEach(session::setAttribute);
        return request;
    }

    private static Map<String, Object> loaded(final SessionDataSerializer node, final byte[] stored) {
        return new HashMap<>(node.fromBytes(stored));
    }

    private static String nonceOf(final byte[] stored, final SessionDataSerializer node) {
        return (String) node.fromBytes(stored).get(OpenIdConnectAuthenticator.OIC_NONCE);
    }

    private void callback(final MockletHttpServletRequest request, final String state) {
        request.setParameter("code", "the-code");
        request.setParameter("state", state);
    }

    // ===================================================================================
    //                                                                           Handshake
    //                                                                           =========
    @Test
    public void test_theLoginStartedOnOneNodeEndsOnAnother() {
        final SessionDataSerializer nodeA = node();
        final SessionDataSerializer nodeB = node();
        final MockletHttpServletRequest request = getMockRequest();
        new OpenIdConnectAuthenticator().getAuthUrl(request);
        final byte[] issued = store(nodeA, request.getSession());

        final Map<String, Object> shared = loaded(nodeB, issued);
        // the three values of the authorization request are what the other node gets
        assertNotNull(shared.get(OpenIdConnectAuthenticator.OIC_STATE));
        assertNotNull(shared.get(OpenIdConnectAuthenticator.OIC_NONCE));
        assertTrue(shared.get(OpenIdConnectAuthenticator.OIC_ISSUED_AT) instanceof Long);

        load(nodeB, issued, request);
        callback(request, (String) shared.get(OpenIdConnectAuthenticator.OIC_STATE));
        final LoginCredential credential = authenticator((String) shared.get(OpenIdConnectAuthenticator.OIC_NONCE)).getLoginCredential();

        assertTrue(credential instanceof OpenIdConnectCredential);
        assertEquals("taro@example.com", ((OpenIdConnectCredential) credential).getUserId());
        assertEquals(1, tokenRequests.get());
    }

    @Test
    public void test_whatTheCallbackConsumedIsNotInTheStoredSession() {
        final SessionDataSerializer nodeA = node();
        final SessionDataSerializer nodeB = node();
        final MockletHttpServletRequest request = getMockRequest();
        new OpenIdConnectAuthenticator().getAuthUrl(request);
        final byte[] issued = store(nodeA, request.getSession());
        final String state = (String) loaded(nodeB, issued).get(OpenIdConnectAuthenticator.OIC_STATE);
        final String nonce = nonceOf(issued, nodeB);

        load(nodeB, issued, request);
        callback(request, state);
        assertTrue(authenticator(nonce).getLoginCredential() instanceof OpenIdConnectCredential);
        final byte[] consumed = store(nodeB, request.getSession());

        final Map<String, Object> after = loaded(nodeA, consumed);
        assertFalse(after.containsKey(OpenIdConnectAuthenticator.OIC_STATE));
        assertFalse(after.containsKey(OpenIdConnectAuthenticator.OIC_NONCE));
        assertFalse(after.containsKey(OpenIdConnectAuthenticator.OIC_ISSUED_AT));

        // the same callback again, on the node that issued the request, with the session as it is stored now
        load(nodeA, consumed, request);
        callback(request, state);
        assertTrue(authenticator(nonce).getLoginCredential() instanceof ActionResponseCredential);
        assertEquals(1, tokenRequests.get(), "the code was sent to the provider again");
        // a callback for a session that waits for none is a restart of the login, not a refused login
        assertEquals(0, loginFailures);
    }

    @Test
    public void test_aCallbackWithTheValuesOfAnOlderCopyIsAcceptedOnlyWhileTheLoginIsFresh() {
        // The residual of the last writer winning: a node that saves a copy it read before the callback was
        // answered writes the state back. It is accepted while fresh, as it would be with no other node, and
        // not after the time a login may take.
        final SessionDataSerializer nodeA = node();
        final MockletHttpServletRequest request = getMockRequest();
        new OpenIdConnectAuthenticator().getAuthUrl(request);
        final HttpSession session = request.getSession();
        final String state = (String) session.getAttribute(OpenIdConnectAuthenticator.OIC_STATE);
        final String nonce = (String) session.getAttribute(OpenIdConnectAuthenticator.OIC_NONCE);
        session.setAttribute(OpenIdConnectAuthenticator.OIC_ISSUED_AT,
                System.currentTimeMillis() - OpenIdConnectAuthenticator.MAX_LOGIN_MILLIS - 1000);
        final byte[] stale = store(nodeA, session);

        load(nodeA, stale, request);
        callback(request, state);
        assertTrue(authenticator(nonce).getLoginCredential() instanceof ActionResponseCredential);
        assertEquals(0, tokenRequests.get(), "the code of an expired login was sent to the provider");
        assertEquals(1, loginFailures);
        // the expired values are consumed as well
        assertNull(request.getSession().getAttribute(OpenIdConnectAuthenticator.OIC_STATE));
        assertNull(request.getSession().getAttribute(OpenIdConnectAuthenticator.OIC_NONCE));
        assertNull(request.getSession().getAttribute(OpenIdConnectAuthenticator.OIC_ISSUED_AT));
    }

    @Test
    public void test_aLoginWithoutTheTimeIsAcceptedAsBefore() {
        // started by a node of the previous version of this plugin, which kept no time
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(OpenIdConnectAuthenticator.OIC_STATE, "the-state");
        request.getSession().setAttribute(OpenIdConnectAuthenticator.OIC_NONCE, "the-nonce");
        callback(request, "the-state");

        assertTrue(authenticator("the-nonce").getLoginCredential() instanceof OpenIdConnectCredential);
    }

    @Test
    public void test_aLoginJustUnderTheLimitIsAccepted() {
        final MockletHttpServletRequest request = getMockRequest();
        request.getSession().setAttribute(OpenIdConnectAuthenticator.OIC_STATE, "the-state");
        request.getSession().setAttribute(OpenIdConnectAuthenticator.OIC_NONCE, "the-nonce");
        request.getSession()
                .setAttribute(OpenIdConnectAuthenticator.OIC_ISSUED_AT,
                        System.currentTimeMillis() - OpenIdConnectAuthenticator.MAX_LOGIN_MILLIS + 60_000L);
        callback(request, "the-state");

        assertTrue(authenticator("the-nonce").getLoginCredential() instanceof OpenIdConnectCredential);
    }

    @Test
    public void test_aRefusedCallbackConsumesTheValuesToo() {
        final MockletHttpServletRequest request = getMockRequest();
        new OpenIdConnectAuthenticator().getAuthUrl(request);
        callback(request, "not-the-state");

        assertTrue(authenticator("n").getLoginCredential() instanceof ActionResponseCredential);
        // the response is only built by the caller, so nothing was issued again and what the refused callback
        // held is gone
        assertNull(request.getSession().getAttribute(OpenIdConnectAuthenticator.OIC_STATE));
        assertNull(request.getSession().getAttribute(OpenIdConnectAuthenticator.OIC_NONCE));
        assertNull(request.getSession().getAttribute(OpenIdConnectAuthenticator.OIC_ISSUED_AT));
        assertEquals(1, loginFailures);
        assertEquals(0, tokenRequests.get());
    }
}
