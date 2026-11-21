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

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codelibs.core.lang.StringUtil;
import org.codelibs.core.misc.DynamicProperties;
import org.codelibs.fess.app.web.base.login.ActionResponseCredential;
import org.codelibs.fess.app.web.base.login.FessLoginAssist.LoginCredentialResolver;
import org.codelibs.fess.crawler.Constants;
import org.codelibs.fess.session.SessionDataSerializer;
import org.codelibs.fess.sso.SsoAuthenticator;
import org.codelibs.fess.sso.SsoResponseType;
import org.codelibs.fess.sso.oic.LogoutTokenValidator.LogoutToken;
import org.codelibs.fess.sso.oic.LogoutTokenValidator.LogoutTokenException;
import org.codelibs.fess.sso.oic.OpenIdConnectCredential.OpenIdUser;
import org.codelibs.fess.util.ComponentUtil;
import org.codelibs.fess.util.LogUtil;
import org.dbflute.optional.OptionalEntity;
import org.dbflute.optional.OptionalThing;
import org.lastaflute.web.login.credential.LoginCredential;
import org.lastaflute.web.response.ActionResponse;
import org.lastaflute.web.response.HtmlResponse;
import org.lastaflute.web.util.LaRequestUtil;

import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonParser;
import com.google.api.client.json.JsonToken;
import com.google.api.client.json.gson.GsonFactory;
import com.google.common.io.BaseEncoding;
import com.google.common.io.BaseEncoding.DecodingException;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * OpenID Connect authenticator for SSO integration.
 */
public class OpenIdConnectAuthenticator implements SsoAuthenticator {

    /**
     * Default constructor.
     */
    public OpenIdConnectAuthenticator() {
        // Default constructor
    }

    private static final Logger logger = LogManager.getLogger(OpenIdConnectAuthenticator.class);

    private static final BaseEncoding BASE64_DECODER = BaseEncoding.base64().withSeparator("\n", 64);

    private static final BaseEncoding BASE64URL_DECODER = BaseEncoding.base64Url().withSeparator("\n", 64);

    /** Configuration key for OpenID Connect authorization server URL. */
    protected static final String OIC_AUTH_SERVER_URL = "oic.auth.server.url";

    /** Configuration key for OpenID Connect client ID. */
    protected static final String OIC_CLIENT_ID = "oic.client.id";

    /** Configuration key for OpenID Connect scope. */
    protected static final String OIC_SCOPE = "oic.scope";

    /** Configuration key for OpenID Connect redirect URL. */
    protected static final String OIC_REDIRECT_URL = "oic.redirect.url";

    /** Configuration key for OpenID Connect token server URL. */
    protected static final String OIC_TOKEN_SERVER_URL = "oic.token.server.url";

    /** Configuration key for OpenID Connect client secret. */
    protected static final String OIC_CLIENT_SECRET = "oic.client.secret";

    /** The name this authenticator is registered under, which is {@code <sso.type>Authenticator}. */
    protected static final String COMPONENT_NAME = "oicAuthenticator";

    /** Configuration key for the {@code jwks_uri} of the provider, which turns back-channel logout on. */
    protected static final String OIC_JWKS_URI = "oic.jwks.uri";

    /** The form parameter that carries the logout token of back-channel logout. */
    protected static final String LOGOUT_TOKEN_PARAMETER = "logout_token";

    /**
     * How long a node trusts what it last read about a logout, in milliseconds. It is how long another node may take to
     * end a session after the node that received the logout.
     */
    protected static final long REVOCATION_CHECK_MILLIS = 30 * 1000L;

    /**
     * The most logouts a node remembers having looked up. A session asks for up to two keys (its {@code sid} and its
     * {@code sub}), and an entry that is evicted while its session is still active is looked up in the index again, on
     * the request path. An entry is a 64 character key and two numbers, about 250 bytes, so 100,000 of them are some 25 MB at
     * most and keep every key of 50,000 concurrent sessions in memory.
     */
    protected static final int MAX_CACHED_REVOCATIONS = 100_000;

    /** The longest JWKS document read, in bytes. */
    protected static final int MAX_JWKS_BYTES = 512 * 1024;

    /** The time the connection to the provider may take, for the JWKS document, in milliseconds. */
    protected static final int JWKS_TIMEOUT_MILLIS = 5000;

    /** The name of the component that serializes the session attributes for the session store. */
    protected static final String SESSION_DATA_SERIALIZER = "sessionDataSerializer";

    /** Session key for OpenID Connect state parameter. */
    protected static final String OIC_STATE = "OIC_STATE";

    /** Session key for OpenID Connect nonce parameter. */
    protected static final String OIC_NONCE = "OIC_NONCE";

    /** Session key for the PKCE code verifier (RFC 7636) of the pending authorization request. */
    protected static final String OIC_CODE_VERIFIER = "OIC_CODE_VERIFIER";

    /**
     * Session key for the time, in epoch milliseconds, the state and the nonce were issued at. A
     * {@link Long}, so that it is shared between nodes like the two values it belongs to.
     */
    protected static final String OIC_ISSUED_AT = "OIC_ISSUED_AT";

    /** How long, in milliseconds, a login may take between the authorization request and its callback. */
    protected static final long MAX_LOGIN_MILLIS = 10 * 60 * 1000L;

    /** Configuration key for OpenID Connect base URL. */
    protected static final String OIC_BASE_URL = "oic.base.url";

    /**
     * Configuration key that turns PKCE (RFC 7636) off when set to {@code false}. Any other value, and an absent
     * key, leave it on.
     */
    protected static final String OIC_PKCE = "oic.pkce";

    /** The number of random bytes of a code verifier; the 43 characters they encode to are the minimum RFC 7636 allows. */
    protected static final int CODE_VERIFIER_BYTES = 32;

    /** Configuration key for the issuer identifier the ID token's {@code iss} claim is compared with. */
    protected static final String OIC_ISSUER = "oic.issuer";

    /** The clock difference, in seconds, tolerated between this host and the provider when {@code exp} is checked. */
    protected static final long CLOCK_SKEW_SECONDS = 300;

    /** The longest request value written to the log as is; a longer one is cut. */
    protected static final int MAX_LOGGED_LENGTH = 100;

    /** Control characters, and the Unicode line and paragraph separators that {@code \p{Cntrl}} does not cover. */
    private static final Pattern UNSAFE_LOG_CHARS = Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");

    /** A dotted-quad address in 127.0.0.0/8, each octet in decimal without leading zeros. */
    private static final Pattern LOOPBACK_IPV4 = Pattern.compile("127(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}");

    /** Source of the code verifiers. */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Set once the log has said that {@code oic.issuer} is not configured. */
    private final AtomicBoolean issuerNotConfiguredLogged = new AtomicBoolean();

    /** Where the logouts received by any node and the logout tokens already used are kept. */
    protected LogoutRevocationStore revocationStore = new LogoutRevocationStore();

    /** The signature keys of the provider. */
    protected final JwksKeySource jwksKeySource =
            new JwksKeySource(this::getOicJwksUri, this::fetchJwks, this::parseJsonObject, this::currentTimeMillis);

    /** Validates the logout token of back-channel logout. */
    protected final LogoutTokenValidator logoutTokenValidator = new LogoutTokenValidator(this::parseJsonObject, jwksKeySource);

    /** What this node last read about a logout, by key: the time of the logout or -1, and when it was read. */
    private final Map<String, long[]> revocationCache = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(final Map.Entry<String, long[]> eldest) {
            return size() > MAX_CACHED_REVOCATIONS;
        }
    });

    /** HTTP transport for OpenID Connect requests. */
    protected final HttpTransport httpTransport = new NetHttpTransport();

    /** JSON factory for OpenID Connect response parsing. */
    protected final JsonFactory jsonFactory = GsonFactory.getDefaultInstance();

    /**
     * Initializes the OpenID Connect authenticator.
     */
    @PostConstruct
    public void init() {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing {}", this.getClass().getSimpleName());
        }
        ComponentUtil.getSsoManager().register(this);
        registerSessionSerializer();
    }

    /**
     * Lets the session store share the logged-in user between nodes, when this Fess has one. It runs after the
     * registration above, so a failure here cannot take the login down; the user is then kept on the node that
     * logged them in. The class is registered whether or not the store is selected, because the format version
     * of the store depends on the registered classes and has to be the same on every node.
     */
    protected void registerSessionSerializer() {
        if (!ComponentUtil.hasComponent(SESSION_DATA_SERIALIZER)) {
            return;
        }
        try {
            ComponentUtil.<SessionDataSerializer> getComponent(SESSION_DATA_SERIALIZER)
                    .register(OpenIdUser.class, new OpenIdUserSerializer());
        } catch (final RuntimeException e) {
            logger.warn("The OpenID Connect user is not shared between nodes by the session store, and the nodes will not agree"
                    + " on the format of the stored sessions: {}", e.getMessage());
        }
    }

    @Override
    public LoginCredential getLoginCredential() {
        return LaRequestUtil.getOptionalRequest().map(request -> {
            if (logger.isDebugEnabled()) {
                logger.debug("Logging in with OpenID Connect Authenticator");
            }
            final HttpSession session = request.getSession(false);
            if (session != null) {
                final String sesState = (String) session.getAttribute(OIC_STATE);
                // Taken out together with the state: both belong to the one authorization request this
                // callback answers, and neither may serve a second callback.
                final String sesNonce = (String) session.getAttribute(OIC_NONCE);
                session.removeAttribute(OIC_NONCE);
                // The PKCE verifier belongs to the same authorization request, and is dropped just the same.
                final String sesCodeVerifier = (String) session.getAttribute(OIC_CODE_VERIFIER);
                session.removeAttribute(OIC_CODE_VERIFIER);
                // The third of the values of one authorization request. A session that was started by a node
                // without it has none, and then only the lifetime of the session limits the login.
                final Object issuedAt = session.getAttribute(OIC_ISSUED_AT);
                session.removeAttribute(OIC_ISSUED_AT);
                final boolean expired = issuedAt instanceof final Long time && System.currentTimeMillis() - time > MAX_LOGIN_MILLIS;
                if (StringUtil.isNotBlank(sesState)) {
                    session.removeAttribute(OIC_STATE);
                    final String code = request.getParameter("code");
                    final String reqState = request.getParameter("state");
                    if (logger.isDebugEnabled()) {
                        // Neither the authorization code nor the state is written: both are credentials of this
                        // login until the callback is answered, and the code is a bearer secret until redeemed.
                        logger.debug("callback: code present={}, state matches the session's={}", StringUtil.isNotBlank(code),
                                sesState.equals(reqState));
                    }
                    if (expired) {
                        logger.warn("The OpenID Connect callback came more than {} seconds after the authorization request.",
                                MAX_LOGIN_MILLIS / 1000);
                        if (StringUtil.isNotBlank(code)) {
                            ComponentUtil.getActivityHelper().loginFailure(OptionalThing.empty());
                        }
                    } else if (sesState.equals(reqState)) {
                        final String error = request.getParameter("error");
                        if (StringUtil.isNotBlank(error)) {
                            // The provider answered this login with an error response (RFC 6749 section
                            // 4.1.2.1). Falling through to a new authorization request would either bounce
                            // between the two servers until the browser gives up, when the provider keeps
                            // refusing, or hand back a code and log the user in anyway, when it refuses only
                            // because the user declined the consent. Report it instead, so the caller shows
                            // the login error.
                            logger.warn("The OpenID provider rejected the authorization request: error={}, error_description={}",
                                    sanitizeForLog(error), sanitizeForLog(request.getParameter("error_description")));
                            return null;
                        }
                        if (StringUtil.isNotBlank(code)) {
                            return processCallback(request, code, sesNonce, sesCodeVerifier);
                        }
                    } else if (StringUtil.isNotBlank(code)) {
                        // A callback that carries a code but not the state of this session is a refused
                        // login (a forged or replayed callback, or one from a login this session no longer
                        // waits for). The caller still gets a fresh authorization request below, as before;
                        // this only leaves the record of it that the null returns above leave through the
                        // caller. Nothing the anonymous caller sent is written to it.
                        ComponentUtil.getActivityHelper().loginFailure(OptionalThing.empty());
                    }
                }
            }

            return new ActionResponseCredential(() -> HtmlResponse.fromRedirectPathAsIs(getAuthUrl(request)));
        }).orElse(null);
    }

    /**
     * Makes a request parameter safe to embed in a log message. The callback endpoint is anonymous and the
     * application log is one event per line, so a line break in a logged value would let any caller start a
     * log line of their own. Control characters are replaced by {@code ?} and a longer value is cut.
     *
     * @param value the request parameter (may be null)
     * @return the value to log, or null if the value is null
     */
    protected static String sanitizeForLog(final String value) {
        if (value == null) {
            return null;
        }
        final String bounded = value.length() > MAX_LOGGED_LENGTH ? value.substring(0, MAX_LOGGED_LENGTH) + "..." : value;
        return UNSAFE_LOG_CHARS.matcher(bounded).replaceAll("?");
    }

    /**
     * Finds the first character of a user name that a name must not contain.
     *
     * <p>The email claim is the user name and the key of the permissions, so it is kept as the provider sent it or
     * not used at all. A line break, a TAB or another control character in it would be copied into every log line
     * and screen that shows the name. The characters refused are those of {@link Character#isISOControl(int)}
     * (Unicode {@code Cc}) and the line and paragraph separators {@code U+2028} and {@code U+2029} ({@code Zl},
     * {@code Zp}). Spaces inside the name, letters of any script and punctuation such as {@code @}, {@code +}
     * and {@code '} are not touched.</p>
     *
     * @param name The name the provider sent.
     * @return A description of the first refused character that does not repeat the name, or null if there is none.
     */
    protected static String describeControlCharacter(final String name) {
        if (name == null) {
            return null;
        }
        for (int i = 0; i < name.length();) {
            final int codePoint = name.codePointAt(i);
            final int type = Character.getType(codePoint);
            if (Character.isISOControl(codePoint) || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR) {
                return String.format("the control character U+%04X at position %d of %d", codePoint, i, name.length());
            }
            i += Character.charCount(codePoint);
        }
        return null;
    }

    /**
     * Gets the authorization URL for OpenID Connect.
     *
     * @param request the HTTP servlet request
     * @return the authorization URL
     */
    protected String getAuthUrl(final HttpServletRequest request) {
        // UUID.randomUUID is backed by SecureRandom and varies in 122 bits. The state is the only
        // thing standing between a login and a forged callback (RFC 6749 section 10.12), and
        // org.codelibs.core.net.UuidUtil, which this used to call, is
        // hex(localIP) + hex(identityHashCode(RANDOM)) + hex((int) (currentTimeMillis() >> 32)) +
        // hex(SecureRandom.nextInt()): its first 16 hex characters are constant for the life of
        // the JVM and under 32 bits actually vary per call. The value is only ever compared with
        // equals() against the copy held in the session, so its length and format are free.
        final String state = UUID.randomUUID().toString();
        // The nonce binds the ID token to this session (OpenID Connect Core 3.1.2.1, 3.1.3.7 item 11): it
        // is sent in the authentication request and has to come back in the id_token. Same source as the
        // state, for the same reason.
        final String nonce = UUID.randomUUID().toString();
        final HttpSession session = request.getSession();
        session.setAttribute(OIC_STATE, state);
        session.setAttribute(OIC_NONCE, nonce);
        session.setAttribute(OIC_ISSUED_AT, System.currentTimeMillis());
        final AuthorizationCodeRequestUrl url = new AuthorizationCodeRequestUrl(getOicAuthServerUrl(), getOicClientId())//
                .setScopes(Arrays.asList(getOicScope()))//
                .setResponseTypes(Arrays.asList("code"))//
                .setRedirectUri(getOicRedirectUrl())//
                .setState(state);
        url.set("nonce", nonce);
        if (isOicPkceEnabled()) {
            // PKCE (RFC 7636) binds the authorization code to this session: the provider keeps the
            // challenge, and only the holder of the verifier can redeem the code at the token endpoint.
            // The verifier stays in the session and never leaves the server until the token request.
            final String codeVerifier = generateCodeVerifier();
            session.setAttribute(OIC_CODE_VERIFIER, codeVerifier);
            url.set("code_challenge", createCodeChallenge(codeVerifier));
            url.set("code_challenge_method", "S256");
        } else {
            // Not left over from an earlier request of this session, which would send a verifier for a
            // challenge this request never made.
            session.removeAttribute(OIC_CODE_VERIFIER);
        }
        return url.build();
    }

    /**
     * Creates a PKCE code verifier: {@value #CODE_VERIFIER_BYTES} random bytes, base64url-encoded without
     * padding, which is 43 characters from the unreserved set (RFC 7636 section 4.1).
     *
     * @return a new code verifier
     */
    protected String generateCodeVerifier() {
        final byte[] bytes = new byte[CODE_VERIFIER_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Derives the {@code S256} code challenge of a verifier: the base64url-encoded SHA-256 of its ASCII
     * bytes, without padding (RFC 7636 section 4.2).
     *
     * @param codeVerifier the code verifier
     * @return the code challenge
     */
    protected static String createCodeChallenge(final String codeVerifier) {
        try {
            final byte[] digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (final NoSuchAlgorithmException e) {
            // Every Java platform has to provide SHA-256.
            throw new IllegalStateException(e);
        }
    }

    /**
     * Tells whether the authorization request carries a PKCE challenge. It does unless {@code oic.pkce} is
     * set to {@code false}.
     *
     * @return false only if PKCE is turned off
     */
    protected boolean isOicPkceEnabled() {
        return !"false".equalsIgnoreCase(ComponentUtil.getSystemProperties().getProperty(OIC_PKCE, "true").trim());
    }

    /**
     * Decodes a Base64 string to bytes.
     *
     * @param base64String the Base64 string to decode
     * @return the decoded bytes, or null if input is null
     */
    protected byte[] decodeBase64(final String base64String) {
        if (base64String == null) {
            return null;
        }
        try {
            return BASE64_DECODER.decode(base64String);
        } catch (final IllegalArgumentException e) {
            if (e.getCause() instanceof DecodingException) {
                return BASE64URL_DECODER.decode(base64String.trim());
            }
            throw e;
        }
    }

    /**
     * Processes the callback from OpenID Connect provider.
     *
     * @param request the HTTP servlet request
     * @param code the authorization code
     * @param expectedNonce the nonce sent in this login's authentication request (may be null)
     * @param codeVerifier the PKCE code verifier whose challenge this login's authentication request carried
     *        (null or blank if it carried none)
     * @return the login credential
     */
    protected LoginCredential processCallback(final HttpServletRequest request, final String code, final String expectedNonce,
            final String codeVerifier) {
        try {
            final TokenResponse tr = getTokenUrl(code, codeVerifier);

            // Everything below reads a document the provider controls. Each malformed shape has to end
            // as a returned null, which the caller turns into the SSO login error, and not as a thrown
            // RuntimeException, which leaves the browser on a system error page.
            if (!(tr.get("id_token") instanceof final String idToken) || StringUtil.isBlank(idToken)) {
                logger.warn("The token response carries no id_token, so there is no user to log in.");
                return null;
            }
            final String[] jwt = idToken.split("\\.");
            if (jwt.length != 3) {
                logger.warn("The id_token is not a JWT: it has {} dot-separated segments instead of 3.", jwt.length);
                return null;
            }
            final String jwtHeader = new String(decodeBase64(jwt[0]), Constants.UTF_8_CHARSET);
            final String jwtClaim = new String(decodeBase64(jwt[1]), Constants.UTF_8_CHARSET);
            final String jwtSignature = new String(decodeBase64(jwt[2]), Constants.UTF_8_CHARSET);

            if (logger.isDebugEnabled()) {
                logger.debug("jwtHeader={}", jwtHeader);
                logger.debug("jwtClaim={}", jwtClaim);
                // The signature is raw bytes, not text. Writing the decoded string put control and
                // invalid-UTF-8 bytes straight into fess.log, which makes the file itself count as
                // binary: grep and the rest of the usual log tooling then skip it silently.
                logger.debug("jwtSignature: {} encoded characters, not validated", jwt[2].length());
            }

            // The signature is deliberately not verified. This id_token was not handed over by the
            // browser: it came straight from the provider's token endpoint in the response to our own
            // request, and OpenID Connect Core 3.1.3.7 (item 6) lets the TLS server validation of that
            // exchange stand in for the signature check. That is why getTokenUrl insists on https.
            // What the specification still requires of the claims -- aud, azp, exp and, when oic.issuer
            // is set, iss -- is checked in validateIdTokenClaims below, and the nonce in validateNonce.

            final Map<String, Object> attributes = new HashMap<>();
            attributes.put("accesstoken", tr.getAccessToken());
            attributes.put("refreshtoken", tr.getRefreshToken() == null ? "null" : tr.getRefreshToken());
            attributes.put("tokentype", tr.getTokenType());
            attributes.put("expire", tr.getExpiresInSeconds());
            attributes.put("jwtheader", jwtHeader);
            attributes.put("jwtclaim", jwtClaim);
            attributes.put("jwtsignature", jwtSignature);

            if (logger.isDebugEnabled()) {
                // Not the whole attribute map: it holds the access token and the refresh token, which
                // are bearer credentials for the provider. The documentation tells an administrator to
                // turn this logger up to debug when a login misbehaves, so whatever it prints ends up
                // in a file that is read, copied into issue reports and shipped to log collectors.
                logger.debug("tokenType={}, expiresInSeconds={}, refreshToken={}", tr.getTokenType(), tr.getExpiresInSeconds(),
                        tr.getRefreshToken() == null ? "absent" : "present");
            }
            parseJwtClaim(jwtClaim, attributes);
            validateIdTokenClaims(attributes, System.currentTimeMillis() / 1000);
            validateNonce(attributes, expectedNonce);

            final OpenIdConnectCredential credential = new OpenIdConnectCredential(attributes);
            if (StringUtil.isBlank(credential.getUserId())) {
                // The user id is the email claim. Without it the credential resolves to a user with a
                // null name, which the login itself accepts and every later request then fails on, so
                // the session has to be refused here rather than created and left unusable.
                logger.warn("The ID token has no email claim that is a string, which is the user id. Check that {} requests it.",
                        OIC_SCOPE);
                return null;
            }
            final String unusable = describeControlCharacter(credential.getUserId());
            if (unusable != null) {
                logger.warn("The email claim, which is the user id, contains {}. It is used as the user name exactly as the provider"
                        + " sent it, so it is not rewritten and the login is refused.", unusable);
                return null;
            }
            return credential;
        } catch (final HttpResponseException e) {
            // The message of this exception is the status line, then the request line (the full token URL,
            // which may carry credentials in its user info or query) and then the whole response body, which
            // can echo the code of this anonymous caller. None of it is logged, not even as a stack trace at
            // debug level: only the status and, for an OAuth error response, its error code.
            logger.warn("Failed to process the OpenID Connect callback: {}", describeTokenEndpointError(e));
        } catch (final IOException | IllegalArgumentException e) {
            // This endpoint is anonymous, so anyone can drive a failing callback. A message keeps a
            // misbehaving provider diagnosable; the stack trace stays behind the debug level so an
            // unauthenticated client cannot fill the log with them.
            logger.warn("Failed to process the OpenID Connect callback: {}", e.getMessage());
            if (logger.isDebugEnabled()) {
                logger.debug("Failed to process callback request.", e);
            }
        }
        return null;
    }

    /**
     * Describes an error answer of the token endpoint for the log: the HTTP status, its reason phrase and,
     * for an OAuth error response, the {@code error} code. Never the request URL or the response body, which
     * {@link HttpResponseException#getMessage()} repeats in full.
     *
     * @param e the error answer
     * @return a one-line description
     */
    protected static String describeTokenEndpointError(final HttpResponseException e) {
        final StringBuilder buf = new StringBuilder("the token endpoint answered HTTP ").append(e.getStatusCode());
        if (StringUtil.isNotBlank(e.getStatusMessage())) {
            buf.append(' ').append(sanitizeForLog(e.getStatusMessage()));
        }
        if (e instanceof final TokenResponseException tre && tre.getDetails() != null && tre.getDetails().getError() != null) {
            buf.append(", error=").append(sanitizeForLog(tre.getDetails().getError()));
        }
        return buf.toString();
    }

    /**
     * Checks the claims of the ID token that OpenID Connect Core 3.1.3.7 requires of a client that
     * has received the token directly from the token endpoint: {@code iss} (only when
     * {@code oic.issuer} is set), {@code aud}, {@code azp} and {@code exp}. A claim of an unexpected
     * type is a failed check, never an exception of another kind.
     *
     * <ul>
     * <li>{@code iss}: when {@code oic.issuer} is set, the claim must equal it exactly. When it is
     * not set the check is skipped, and the log says so once per authenticator.</li>
     * <li>{@code aud}: a string or an array of strings that contains the configured client id.
     * Without a configured client id nothing can match, so the token is refused.</li>
     * <li>{@code azp}: when present, it must be the client id. A token that lists more than one
     * audience must carry it.</li>
     * <li>{@code exp}: required, and a number. The token is accepted while
     * {@code nowSeconds < exp + CLOCK_SKEW_SECONDS}.</li>
     * </ul>
     *
     * @param claims the claim set of the ID token
     * @param nowSeconds the current time, in seconds since the epoch
     * @throws IllegalArgumentException if a check fails; the message names the reason
     */
    protected void validateIdTokenClaims(final Map<String, Object> claims, final long nowSeconds) {
        final String expectedIssuer = getOicIssuer();
        if (StringUtil.isBlank(expectedIssuer)) {
            if (issuerNotConfiguredLogged.compareAndSet(false, true)) {
                logger.warn("{} is not set, so the iss claim of the ID token is not checked. Set it to the issuer value of the"
                        + " provider's /.well-known/openid-configuration.", OIC_ISSUER);
            }
        } else if (!expectedIssuer.equals(claims.get("iss"))) {
            throw new IllegalArgumentException("The ID token was not issued by the configured issuer: iss="
                    + sanitizeForLog(String.valueOf(claims.get("iss"))) + ", " + OIC_ISSUER + "=" + sanitizeForLog(expectedIssuer));
        }

        final String clientId = getOicClientId();
        if (StringUtil.isBlank(clientId)) {
            throw new IllegalArgumentException(OIC_CLIENT_ID + " is not set, so the audience of the ID token cannot be checked.");
        }
        final Object aud = claims.get("aud");
        final List<String> audiences = new ArrayList<>();
        if (aud instanceof final String single) {
            audiences.add(single);
        } else if (aud instanceof final List<?> list) {
            for (final Object element : list) {
                if (element instanceof final String audience) {
                    audiences.add(audience);
                }
            }
        }
        if (!audiences.contains(clientId)) {
            throw new IllegalArgumentException("The ID token was not issued for this client: aud=" + sanitizeForLog(String.valueOf(aud))
                    + ", " + OIC_CLIENT_ID + "=" + sanitizeForLog(clientId));
        }

        final Object azp = claims.get("azp");
        if (azp != null && !clientId.equals(azp)) {
            throw new IllegalArgumentException(
                    "The ID token was issued to another authorized party: azp=" + sanitizeForLog(String.valueOf(azp)));
        }
        if (azp == null && aud instanceof final List<?> list && list.size() > 1) {
            throw new IllegalArgumentException("The ID token lists several audiences but has no azp claim.");
        }

        if (!(claims.get("exp") instanceof final Number exp)) {
            throw new IllegalArgumentException("The ID token has no numeric exp claim.");
        }
        // Compared as doubles: a Long near Long.MAX_VALUE plus the skew would wrap around. The negated
        // form also refuses NaN.
        if (!(nowSeconds < exp.doubleValue() + CLOCK_SKEW_SECONDS)) {
            throw new IllegalArgumentException(
                    "The ID token has expired: exp=" + exp + ", now=" + nowSeconds + ", allowed clock skew=" + CLOCK_SKEW_SECONDS + "s.");
        }
    }

    /**
     * Checks that the ID token answers the authentication request this session sent: its {@code nonce} claim
     * has to equal the nonce that request carried (OpenID Connect Core 3.1.3.7 item 11). A token without the
     * claim is refused too, because a client that sent a nonce is entitled to find it in the token.
     *
     * @param claims the claim set of the ID token
     * @param expectedNonce the nonce kept in the session for this login, null or blank if there was none
     * @throws IllegalArgumentException if the nonce is missing from the session or the token, or differs
     */
    protected void validateNonce(final Map<String, Object> claims, final String expectedNonce) {
        if (StringUtil.isBlank(expectedNonce)) {
            throw new IllegalArgumentException("No nonce was issued for this login, so the ID token cannot be matched to it.");
        }
        // Neither value is logged: the token's claim is the provider's input and the expected one is this
        // session's secret.
        if (!(claims.get("nonce") instanceof final String nonce)) {
            throw new IllegalArgumentException("The ID token has no nonce claim that is a string.");
        }
        if (!expectedNonce.equals(nonce)) {
            throw new IllegalArgumentException("The nonce of the ID token is not the one sent in the authentication request.");
        }
    }

    /**
     * Parses the JWT claim and extracts attributes.
     *
     * @param jwtClaim the JWT claim string
     * @param attributes the attributes map to populate
     * @throws IOException if an I/O error occurs
     * @throws IllegalArgumentException if the claim string is not a complete JSON object
     */
    protected void parseJwtClaim(final String jwtClaim, final Map<String, Object> attributes) throws IOException {
        try (final JsonParser jsonParser = jsonFactory.createJsonParser(jwtClaim)) {
            jsonParser.nextToken();
            attributes.putAll(parseObject(jsonParser));
        }
    }

    /**
     * Parses primitive values from JSON parser.
     *
     * @param jsonParser the JSON parser
     * @return the parsed primitive value
     * @throws IOException if an I/O error occurs
     */
    protected Object parsePrimitive(final JsonParser jsonParser) throws IOException {
        final JsonToken token = jsonParser.getCurrentToken();
        return switch (token) {
        case VALUE_STRING -> jsonParser.getText();
        case VALUE_NUMBER_INT -> parseInteger(jsonParser);
        case VALUE_NUMBER_FLOAT -> jsonParser.getDoubleValue();
        case VALUE_TRUE -> true;
        case VALUE_FALSE -> false;
        case VALUE_NULL -> null;
        default -> null; // Or throw an exception if unexpected token
        };
    }

    /**
     * Reads a number the JSON parser reports as an integer. The parser decides that by the absence of a
     * decimal point alone, so a value such as {@code 4e9}, or an integer beyond the range of a long, arrives
     * here too and is read as a double.
     *
     * @param jsonParser the JSON parser, positioned on the number
     * @return a {@link Long}, or a {@link Double} when the text is not a long
     * @throws IOException if an I/O error occurs
     */
    private Object parseInteger(final JsonParser jsonParser) throws IOException {
        try {
            return jsonParser.getLongValue();
        } catch (final NumberFormatException e) {
            return jsonParser.getDoubleValue();
        }
    }

    /**
     * Moves the JSON parser to the next token, which the document has to still hold. At the end of the
     * input the parser answers {@code null} again and again, so a loop that waits for a closing token would
     * never leave.
     *
     * @param jsonParser the JSON parser
     * @return the next token, never null
     * @throws IOException if an I/O error occurs
     * @throws IllegalArgumentException if the document ends here
     */
    private JsonToken requireNextToken(final JsonParser jsonParser) throws IOException {
        final JsonToken token = jsonParser.nextToken();
        if (token == null) {
            throw new IllegalArgumentException("The JSON document ends before it is complete.");
        }
        return token;
    }

    /**
     * Parses array values from JSON parser.
     *
     * @param jsonParser the JSON parser, positioned on the start of the array
     * @return the parsed array as a list
     * @throws IOException if an I/O error occurs
     * @throws IllegalArgumentException if the parser is not on the start of an array, or the document ends inside it
     */
    protected Object parseArray(final JsonParser jsonParser) throws IOException {
        if (jsonParser.getCurrentToken() != JsonToken.START_ARRAY) {
            throw new IllegalArgumentException("The JSON value is not an array.");
        }
        final List<Object> list = new ArrayList<>();
        while (requireNextToken(jsonParser) != JsonToken.END_ARRAY) {
            if (jsonParser.getCurrentToken() == JsonToken.START_OBJECT) {
                list.add(parseObject(jsonParser));
            } else if (jsonParser.getCurrentToken() == JsonToken.START_ARRAY) {
                list.add(parseArray(jsonParser)); // Nested array
            } else {
                list.add(parsePrimitive(jsonParser));
            }
        }

        return list;
    }

    /**
     * Parses object values from JSON parser.
     *
     * @param jsonParser the JSON parser, positioned on the start of the object
     * @return the parsed object as a map
     * @throws IOException if an I/O error occurs
     * @throws IllegalArgumentException if the parser is not on the start of an object, or the document ends inside it
     */
    protected Map<String, Object> parseObject(final JsonParser jsonParser) throws IOException {
        if (jsonParser.getCurrentToken() != JsonToken.START_OBJECT) {
            throw new IllegalArgumentException("The JSON value is not an object.");
        }
        final Map<String, Object> nestedMap = new HashMap<>();
        JsonToken token;
        while ((token = requireNextToken(jsonParser)) != JsonToken.END_OBJECT) {
            if (token != JsonToken.FIELD_NAME) {
                throw new IllegalArgumentException("The JSON object has a " + token + " where a field name is expected.");
            }
            final String fieldName = jsonParser.getCurrentName();
            requireNextToken(jsonParser); // Move to the value of the current field

            if (jsonParser.getCurrentToken() == JsonToken.START_ARRAY) {
                nestedMap.put(fieldName, parseArray(jsonParser));
            } else if (jsonParser.getCurrentToken() == JsonToken.START_OBJECT) {
                nestedMap.put(fieldName, parseObject(jsonParser));
            } else {
                nestedMap.put(fieldName, parsePrimitive(jsonParser));
            }
        }
        return nestedMap;
    }

    /**
     * Gets the token response from the OpenID Connect provider.
     *
     * @param code the authorization code
     * @param codeVerifier the PKCE code verifier of the authorization request, sent as {@code code_verifier}
     *        (null or blank if the request carried no challenge, and then nothing is sent)
     * @return the token response
     * @throws IOException if an I/O error occurs, or the token response is cut off
     * @throws IllegalArgumentException if the token server URL is not acceptable, see {@link #requireSecureTokenEndpoint(String)}
     */
    protected TokenResponse getTokenUrl(final String code, final String codeVerifier) throws IOException {
        final String tokenServerUrl = getOicTokenServerUrl();
        requireSecureTokenEndpoint(tokenServerUrl);
        try {
            final AuthorizationCodeTokenRequest request =
                    new AuthorizationCodeTokenRequest(httpTransport, jsonFactory, toGenericUrl(tokenServerUrl), code)//
                            .setGrantType("authorization_code")//
                            .setRedirectUri(getOicRedirectUrl());
            request.set("client_id", getOicClientId());
            request.set("client_secret", getOicClientSecret());
            if (StringUtil.isNotBlank(codeVerifier)) {
                request.set("code_verifier", codeVerifier);
            }
            return request.execute();
        } catch (final NullPointerException e) {
            // The JSON parser of the HTTP client dereferences the missing token when the response ends
            // right after a field name or its colon. Every other truncation is an IOException, so this
            // one is made the same, which processCallback turns into a refused login.
            throw new IOException("The token response is not a complete JSON document.", e);
        }
    }

    private static GenericUrl toGenericUrl(final String url) {
        return toGenericUrl(url, OIC_TOKEN_SERVER_URL);
    }

    private static GenericUrl toGenericUrl(final String url, final String key) {
        try {
            return new GenericUrl(url);
        } catch (final IllegalArgumentException e) {
            // Dropped, not chained: the message of the MalformedURLException inside repeats part of the URL,
            // which may carry credentials.
            throw new IllegalArgumentException(key + " is not a valid URL");
        }
    }

    /**
     * Refuses a token endpoint that is not reached over TLS. The ID token is not signature-checked
     * because it comes straight from this endpoint (see {@link #processCallback}), and the client
     * secret is sent to it, so a plain http endpoint would leave both unprotected. {@code http} is
     * accepted only when the host is the literal {@code localhost}, an address in 127.0.0.0/8 or
     * {@code ::1}, for a provider on the same machine; nothing is resolved to decide that. A
     * {@code #fragment} is refused as well: the token request cannot be built with one, and the
     * library says so with an exception that has no message.
     *
     * @param url the token endpoint URL (may be null)
     * @throws IllegalArgumentException if the URL is not https, or http for another host, or if it
     *         carries a fragment; the message does not repeat the URL, which may carry credentials
     */
    protected void requireSecureTokenEndpoint(final String url) {
        requireSecureUrl(url, OIC_TOKEN_SERVER_URL);
    }

    /**
     * Refuses an endpoint that is not reached over TLS, by the rule of {@link #requireSecureTokenEndpoint(String)}.
     * The keys that verify a logout token are only as trustworthy as the way they were fetched.
     *
     * @param url the URL (may be null)
     * @param key the name of the setting that holds it, which the message names instead of the URL
     * @throws IllegalArgumentException if the URL is not https, or http for another host than a loopback one, or carries a fragment
     */
    protected void requireSecureUrl(final String url, final String key) {
        if (!isSecureTokenEndpoint(url)) {
            throw new IllegalArgumentException(key + " must be https (http is accepted only for localhost, 127.x.x.x and ::1)");
        }
        // The URL parsed as a URI above, where a '#' can only begin the fragment.
        if (url.indexOf('#') >= 0) {
            throw new IllegalArgumentException(key + " must not contain a #fragment");
        }
    }

    private static boolean isSecureTokenEndpoint(final String url) {
        if (url == null) {
            return false;
        }
        final URI uri;
        try {
            // java.net.URL, which GenericUrl uses, ignores leading and trailing whitespace; so does this.
            uri = URI.create(url.trim());
        } catch (final IllegalArgumentException e) {
            // Dropped, not chained: the parser's message repeats the URL, which may carry credentials.
            return false;
        }
        final String scheme = uri.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return true;
        }
        final String host = uri.getHost();
        return "http".equalsIgnoreCase(scheme) && host != null && ("localhost".equalsIgnoreCase(host) || "[::1]".equals(host)
                || "::1".equals(host) || LOOPBACK_IPV4.matcher(host).matches());
    }

    /**
     * Gets the OpenID Connect client secret.
     *
     * @return the client secret
     */
    protected String getOicClientSecret() {
        return ComponentUtil.getSystemProperties().getProperty(OIC_CLIENT_SECRET, StringUtil.EMPTY);
    }

    /**
     * Gets the OpenID Connect token server URL.
     *
     * @return the token server URL
     */
    protected String getOicTokenServerUrl() {
        return ComponentUtil.getSystemProperties().getProperty(OIC_TOKEN_SERVER_URL, "https://accounts.google.com/o/oauth2/token");
    }

    /**
     * Gets the OpenID Connect redirect URL.
     *
     * @return the redirect URL
     */
    protected String getOicRedirectUrl() {
        final String redirectUrl = ComponentUtil.getSystemProperties().getProperty(OIC_REDIRECT_URL);
        return redirectUrl != null ? redirectUrl : buildDefaultRedirectUrl();
    }

    /**
     * Builds a default redirect URL for OpenID Connect based on the environment.
     * Uses the configured base URL or defaults to http://localhost:8080 for compatibility
     * with common OIDC provider configurations.
     *
     * @return the default redirect URL
     */
    protected String buildDefaultRedirectUrl() {
        final DynamicProperties systemProperties = ComponentUtil.getSystemProperties();
        String baseUrl = systemProperties.getProperty(OIC_BASE_URL);
        if (StringUtil.isBlank(baseUrl)) {
            baseUrl = "http://localhost:8080";
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl + "/sso/";
    }

    /**
     * Gets the OpenID Connect scope.
     *
     * @return the scope
     */
    protected String getOicScope() {
        return ComponentUtil.getSystemProperties().getProperty(OIC_SCOPE, StringUtil.EMPTY);
    }

    /**
     * Gets the OpenID Connect client ID.
     *
     * @return the client ID
     */
    protected String getOicClientId() {
        return ComponentUtil.getSystemProperties().getProperty(OIC_CLIENT_ID, StringUtil.EMPTY);
    }

    /**
     * Gets the issuer identifier the ID token's {@code iss} claim has to equal.
     *
     * @return the issuer, trimmed; empty when the check is not configured
     */
    protected String getOicIssuer() {
        return ComponentUtil.getSystemProperties().getProperty(OIC_ISSUER, StringUtil.EMPTY).trim();
    }

    /**
     * Gets the OpenID Connect authorization server URL.
     *
     * @return the authorization server URL
     */
    protected String getOicAuthServerUrl() {
        return ComponentUtil.getSystemProperties().getProperty(OIC_AUTH_SERVER_URL, "https://accounts.google.com/o/oauth2/auth");
    }

    /**
     * Gets the {@code jwks_uri} of the provider, where the keys that sign its logout tokens are.
     *
     * @return the URI, trimmed; empty when back-channel logout is not turned on
     */
    protected String getOicJwksUri() {
        return ComponentUtil.getSystemProperties().getProperty(OIC_JWKS_URI, StringUtil.EMPTY).trim();
    }

    // ===================================================================================
    //                                                            Back-Channel Logout 1.0
    //                                                            ======================

    @Override
    public ActionResponse getResponse(final SsoResponseType responseType) {
        if (responseType != SsoResponseType.LOGOUT) {
            return null;
        }
        // Only a POST that carries a logout token is back-channel logout; anything else keeps the answer it had,
        // which is that this authenticator has no single logout endpoint.
        return LaRequestUtil.getOptionalRequest()
                .filter(request -> "POST".equalsIgnoreCase(request.getMethod()) && request.getParameter(LOGOUT_TOKEN_PARAMETER) != null)
                .map(this::handleBackchannelLogout)
                .orElse(null);
    }

    /**
     * Answers an OpenID Connect Back-Channel Logout 1.0 request: records that the login the token names has ended at
     * the provider, so that every node ends the session when it next looks at it.
     *
     * <p>The answer is {@code 200} if the logout was recorded and {@code 400} otherwise, an empty body either way and
     * {@code Cache-Control: no-store} (section 2.8). The endpoint is anonymous, so a refused request is logged in one
     * line with the failed check and nothing of the token.</p>
     *
     * @param request the request
     * @return the response
     */
    protected ActionResponse handleBackchannelLogout(final HttpServletRequest request) {
        try {
            if (StringUtil.isBlank(getOicJwksUri())) {
                // Every installation of this authenticator has no such key until it turns the feature on, and the endpoint
                // is anonymous: one message per JVM, not one per request.
                logRefusal("jwks-unset", OIC_JWKS_URI + " is not set, so back-channel logout is not turned on.");
                return logoutAnswer(HttpServletResponse.SC_BAD_REQUEST);
            }
            final long now = currentTimeMillis();
            final LogoutToken token = logoutTokenValidator.validate(request.getParameter(LOGOUT_TOKEN_PARAMETER), getOicIssuer(),
                    getOicClientId(), now / 1000);
            final String tokenKey = LogoutRevocationStore.tokenKey(token.issuer(), token.jti());
            if (!revocationStore.markTokenUsed(tokenKey, now)) {
                throw new LogoutTokenException("The logout token was used before.");
            }
            try {
                // A session id names one session. Without it the subject names every session of the user, and
                // the sessions opened after this time are not among them.
                final String key = token.sessionId() != null ? LogoutRevocationStore.sessionKey(token.issuer(), token.sessionId())
                        : LogoutRevocationStore.subjectKey(token.issuer(), token.subject());
                revocationStore.revoke(key, now);
                revocationCache.put(key, new long[] { now, now });
            } catch (final RuntimeException e) {
                // The provider may send the token again, and has to be able to.
                try {
                    revocationStore.forgetToken(tokenKey);
                } catch (final RuntimeException ignored) {
                    logger.debug("The logout token could not be forgotten.", ignored);
                }
                throw e;
            }
            if (logger.isInfoEnabled()) {
                logger.info("Recorded a back-channel logout: by={}", token.sessionId() != null ? "sid" : "sub");
            }
            return logoutAnswer(HttpServletResponse.SC_OK);
        } catch (final LogoutTokenException e) {
            // The message names the failed check and nothing of the token, so it is also the kind of the refusal.
            logRefusal(e.getMessage(), e.getMessage());
        } catch (final RuntimeException e) {
            logRefusal("failure:" + e.getClass().getName(),
                    "Failed to process a back-channel logout request: " + sanitizeForLog(e.getMessage()));
            if (logger.isDebugEnabled()) {
                logger.debug("Failed to process a back-channel logout request.", e);
            }
        }
        return logoutAnswer(HttpServletResponse.SC_BAD_REQUEST);
    }

    /**
     * Logs a refused back-channel logout request. The endpoint is anonymous, so anyone can make a refusal: the first of
     * each kind is a warning, the rest are debug messages.
     *
     * @param kind what the refusals that are the same have in common
     * @param message the message, which holds nothing of the token
     */
    private static void logRefusal(final String kind, final String message) {
        if (!LogUtil.warnOnce(logger, "backchannel-logout:" + kind,
                "Refused a back-channel logout request (the next ones of this kind" + " are logged at debug level): {}", message)
                && logger.isDebugEnabled()) {
            logger.debug("Refused a back-channel logout request: {}", message);
        }
    }

    private static ActionResponse logoutAnswer(final int status) {
        return HtmlResponse.asEmptyBody().httpStatus(status).header("Cache-Control", "no-store");
    }

    /**
     * Tells whether the provider has logged a login out through back-channel logout.
     *
     * <p>Asked when the session is looked up, by every request of a logged-in user ({@code FessUser#isExpired}). The
     * answer comes from this node's memory for {@value #REVOCATION_CHECK_MILLIS} ms and from the coordinator index after
     * that, so a logout recorded by another node is seen within that time. A login is ended if its {@code sid} was logged
     * out, or if its {@code sub} was logged out after the login was opened. If the index cannot be read nothing is ended:
     * the session of a user is not worth more than a provider that says nothing.</p>
     *
     * @param user the user of the session
     * @return true if the login has ended
     */
    public boolean isLoginRevoked(final OpenIdUser user) {
        final String issuer = user.getIssuer();
        if (issuer == null || StringUtil.isBlank(getOicJwksUri())) {
            return false;
        }
        final long now = currentTimeMillis();
        if (user.getSessionId() != null && findRevokedAt(LogoutRevocationStore.sessionKey(issuer, user.getSessionId()), now) >= 0) {
            return true;
        }
        if (user.getSubject() != null) {
            final long revokedAt = findRevokedAt(LogoutRevocationStore.subjectKey(issuer, user.getSubject()), now);
            return revokedAt >= 0 && user.getLoginTime() <= revokedAt;
        }
        return false;
    }

    /**
     * Returns the current time.
     *
     * @return the current time in milliseconds
     */
    protected long currentTimeMillis() {
        return System.currentTimeMillis();
    }

    private long findRevokedAt(final String key, final long now) {
        final long[] cached = revocationCache.get(key);
        if (cached != null && now - cached[1] < REVOCATION_CHECK_MILLIS) {
            return cached[0];
        }
        // If the index cannot be read, the last answer stands (not logged out when there is none): this runs on the request
        // path of every user, so a failing, slow or missing index must neither fail the request nor end the sessions.
        long revokedAt = cached != null ? cached[0] : -1;
        try {
            revokedAt = revocationStore.findRevokedAt(key, now);
        } catch (final RuntimeException e) {
            // Remembered like an answer, so that a failing index is not asked again by every request.
            LogUtil.warnOnce(logger, "revocation-lookup",
                    "Could not look up the back-channel logouts, so no session is ended by one" + " until the index can be read: {}",
                    sanitizeForLog(e.getClass().getSimpleName() + " " + e.getMessage()));
        }
        revocationCache.put(key, new long[] { revokedAt, now });
        return revokedAt;
    }

    /**
     * Reads a JSON object.
     *
     * @param json the text
     * @return the members of the object
     * @throws IllegalArgumentException if the text is not a JSON object
     */
    protected Map<String, Object> parseJsonObject(final String json) {
        try (final JsonParser jsonParser = jsonFactory.createJsonParser(json)) {
            jsonParser.nextToken();
            return parseObject(jsonParser);
        } catch (final IOException | RuntimeException e) {
            throw new IllegalArgumentException("The text is not a JSON object.");
        }
    }

    /**
     * Reads the JWKS document of the provider.
     *
     * @param url the {@code jwks_uri}
     * @return the document
     * @throws IllegalStateException if the URL is not acceptable (see {@link #requireSecureUrl(String, String)}) or the
     *         document cannot be read; the message says why and does not repeat the URL, which may carry credentials
     */
    protected String fetchJwks(final String url) {
        try {
            requireSecureUrl(url, OIC_JWKS_URI);
            final HttpRequest request = httpTransport.createRequestFactory()
                    .buildGetRequest(toGenericUrl(url, OIC_JWKS_URI))
                    .setFollowRedirects(false)
                    .setConnectTimeout(JWKS_TIMEOUT_MILLIS)
                    .setReadTimeout(JWKS_TIMEOUT_MILLIS)
                    .setNumberOfRetries(0);
            final HttpResponse response = request.execute();
            try {
                return JwksKeySource.readLimited(response.getContent(), MAX_JWKS_BYTES);
            } finally {
                response.disconnect();
            }
        } catch (final HttpResponseException e) {
            throw new IllegalStateException("The JWKS endpoint answered HTTP " + e.getStatusCode() + ".");
        } catch (final IOException | IllegalArgumentException e) {
            throw new IllegalStateException("The JWKS document could not be read: " + e.getClass().getSimpleName());
        }
    }

    @Override
    public void resolveCredential(final LoginCredentialResolver resolver) {
        resolver.resolve(OpenIdConnectCredential.class, credential -> OptionalEntity.of(credential.getUser()));
    }

}
