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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
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
import org.codelibs.fess.sso.SsoAuthenticator;
import org.codelibs.fess.util.ComponentUtil;
import org.dbflute.optional.OptionalEntity;
import org.lastaflute.web.login.credential.LoginCredential;
import org.lastaflute.web.response.HtmlResponse;
import org.lastaflute.web.util.LaRequestUtil;

import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.http.GenericUrl;
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

    /** Session key for OpenID Connect state parameter. */
    protected static final String OIC_STATE = "OIC_STATE";

    /** Session key for OpenID Connect nonce parameter. */
    protected static final String OIC_NONCE = "OIC_NONCE";

    /** Configuration key for OpenID Connect base URL. */
    protected static final String OIC_BASE_URL = "oic.base.url";

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

    /** Set once the log has said that {@code oic.issuer} is not configured. */
    private final AtomicBoolean issuerNotConfiguredLogged = new AtomicBoolean();

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
                if (StringUtil.isNotBlank(sesState)) {
                    session.removeAttribute(OIC_STATE);
                    final String code = request.getParameter("code");
                    final String reqState = request.getParameter("state");
                    if (logger.isDebugEnabled()) {
                        logger.debug("code: {}, state(request): {}, state(session): {}", sanitizeForLog(code), sanitizeForLog(reqState),
                                sesState);
                    }
                    if (sesState.equals(reqState)) {
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
                            return processCallback(request, code, sesNonce);
                        }
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
        return new AuthorizationCodeRequestUrl(getOicAuthServerUrl(), getOicClientId())//
                .setScopes(Arrays.asList(getOicScope()))//
                .setResponseTypes(Arrays.asList("code"))//
                .setRedirectUri(getOicRedirectUrl())//
                .setState(state)//
                .set("nonce", nonce)//
                .build();
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
     * @return the login credential
     */
    protected LoginCredential processCallback(final HttpServletRequest request, final String code, final String expectedNonce) {
        try {
            final TokenResponse tr = getTokenUrl(code);

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
     * @return the token response
     * @throws IOException if an I/O error occurs, or the token response is cut off
     * @throws IllegalArgumentException if the token server URL is not acceptable, see {@link #requireSecureTokenEndpoint(String)}
     */
    protected TokenResponse getTokenUrl(final String code) throws IOException {
        final String tokenServerUrl = getOicTokenServerUrl();
        requireSecureTokenEndpoint(tokenServerUrl);
        try {
            return new AuthorizationCodeTokenRequest(httpTransport, jsonFactory, toGenericUrl(tokenServerUrl), code)//
                    .setGrantType("authorization_code")//
                    .setRedirectUri(getOicRedirectUrl())//
                    .set("client_id", getOicClientId())//
                    .set("client_secret", getOicClientSecret())//
                    .execute();
        } catch (final NullPointerException e) {
            // The JSON parser of the HTTP client dereferences the missing token when the response ends
            // right after a field name or its colon. Every other truncation is an IOException, so this
            // one is made the same, which processCallback turns into a refused login.
            throw new IOException("The token response is not a complete JSON document.", e);
        }
    }

    private static GenericUrl toGenericUrl(final String url) {
        try {
            return new GenericUrl(url);
        } catch (final IllegalArgumentException e) {
            // Dropped, not chained: the message of the MalformedURLException inside repeats part of the URL,
            // which may carry credentials.
            throw new IllegalArgumentException(OIC_TOKEN_SERVER_URL + " is not a valid URL");
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
        if (!isSecureTokenEndpoint(url)) {
            throw new IllegalArgumentException(
                    OIC_TOKEN_SERVER_URL + " must be https (http is accepted only for localhost, 127.x.x.x and ::1)");
        }
        // The URL parsed as a URI above, where a '#' can only begin the fragment.
        if (url.indexOf('#') >= 0) {
            throw new IllegalArgumentException(OIC_TOKEN_SERVER_URL + " must not contain a #fragment");
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

    @Override
    public void resolveCredential(final LoginCredentialResolver resolver) {
        resolver.resolve(OpenIdConnectCredential.class, credential -> OptionalEntity.of(credential.getUser()));
    }

}
