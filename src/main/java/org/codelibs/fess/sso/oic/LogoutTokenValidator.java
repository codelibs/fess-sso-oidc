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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.codelibs.core.lang.StringUtil;

/**
 * Validates the {@code logout_token} of OpenID Connect Back-Channel Logout 1.0, section 2.6.
 *
 * <p>The checks, in the order the specification lists them: the token is a JWS signed by a key of the provider with
 * an algorithm this class accepts (RS256, RS384, RS512, ES256, ES384, ES512, never {@code none} or an HMAC); {@code iss}
 * is the configured issuer; {@code aud} holds the client id; {@code iat} and {@code exp} are numbers, the token has
 * not expired and was not issued in the future (both with the clock skew of the ID token check) nor more than
 * {@value #MAX_AGE_SECONDS} seconds ago; {@code jti} is a string; {@code events} has the member
 * {@value #BACKCHANNEL_LOGOUT_EVENT} with a JSON object as its value; {@code nonce} is absent; and at least one of
 * {@code sub} and {@code sid} is a string. That a {@code jti} is not used twice is for the caller, which owns the
 * place the used ones are remembered.</p>
 *
 * <p>Nothing of the token is put into an exception message: the endpoint is anonymous, and the message ends up in the
 * log.</p>
 */
public class LogoutTokenValidator {

    /** The member of {@code events} that marks a logout token. */
    public static final String BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

    /** The longest token accepted, in characters. A real one is a few hundred bytes. */
    public static final int MAX_TOKEN_LENGTH = 16 * 1024;

    /** How long after its {@code iat} a token is still accepted, in seconds. It bounds how long a used {@code jti} has to be remembered. */
    public static final long MAX_AGE_SECONDS = 60 * 60;

    /** The clock difference tolerated between this host and the provider, in seconds. */
    public static final long CLOCK_SKEW_SECONDS = OpenIdConnectAuthenticator.CLOCK_SKEW_SECONDS;

    private final Function<String, Map<String, Object>> jsonParser;

    private final JwksKeySource keySource;

    /**
     * Creates the validator.
     *
     * @param jsonParser parses a JSON object, and throws {@link IllegalArgumentException} for any other text
     * @param keySource the signature keys of the provider
     */
    public LogoutTokenValidator(final Function<String, Map<String, Object>> jsonParser, final JwksKeySource keySource) {
        this.jsonParser = jsonParser;
        this.keySource = keySource;
    }

    /**
     * Validates a logout token.
     *
     * @param token the compact serialization of the token
     * @param issuer the issuer the token has to carry
     * @param clientId the client id the token has to be addressed to
     * @param nowSeconds the current time in seconds since the epoch
     * @return the claims that are used
     * @throws LogoutTokenException if the token is not acceptable; the message names the failed check and nothing of the token
     */
    public LogoutToken validate(final String token, final String issuer, final String clientId, final long nowSeconds) {
        if (StringUtil.isBlank(issuer)) {
            throw new LogoutTokenException("oic.issuer is not set, so the issuer of the logout token cannot be checked.");
        }
        if (StringUtil.isBlank(clientId)) {
            throw new LogoutTokenException("oic.client.id is not set, so the audience of the logout token cannot be checked.");
        }
        if (StringUtil.isBlank(token) || token.length() > MAX_TOKEN_LENGTH) {
            throw new LogoutTokenException("The logout token is empty or too long.");
        }
        final String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new LogoutTokenException("The logout token is not a JWS with 3 parts.");
        }
        final Map<String, Object> header = parseSegment(parts[0], "header");
        verifySignature(header, parts);
        final Map<String, Object> claims = parseSegment(parts[1], "claims");
        return checkClaims(claims, issuer, clientId, nowSeconds);
    }

    private Map<String, Object> parseSegment(final String segment, final String name) {
        try {
            return jsonParser.apply(new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8));
        } catch (final IllegalArgumentException e) {
            throw new LogoutTokenException("The " + name + " of the logout token is not a base64url encoded JSON object.");
        }
    }

    private void verifySignature(final Map<String, Object> header, final String[] parts) {
        final String algorithm = header.get("alg") instanceof final String alg ? alg : "";
        final String jcaName = jcaName(algorithm);
        if (jcaName == null) {
            throw new LogoutTokenException("The signature algorithm of the logout token is not accepted.");
        }
        final byte[] signature;
        try {
            signature = Base64.getUrlDecoder().decode(parts[2]);
        } catch (final IllegalArgumentException e) {
            throw new LogoutTokenException("The signature of the logout token is not base64url encoded.");
        }
        final String keyType = algorithm.startsWith("RS") ? "RSA" : "EC";
        final List<PublicKey> keys;
        try {
            keys = keySource.find(header.get("kid") instanceof final String kid ? kid : null, keyType);
        } catch (final IllegalStateException e) {
            throw new LogoutTokenException("No signature key of the provider is available: " + e.getMessage());
        }
        final byte[] signed = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        for (final PublicKey key : keys) {
            try {
                final Signature verifier = Signature.getInstance(jcaName);
                verifier.initVerify(key);
                verifier.update(signed);
                if (verifier.verify(signature)) {
                    return;
                }
            } catch (final GeneralSecurityException e) {
                // A signature of the wrong shape for the key is a signature that does not verify.
                continue;
            }
        }
        throw new LogoutTokenException("The signature of the logout token does not verify.");
    }

    private static String jcaName(final String algorithm) {
        return switch (algorithm) {
        case "RS256" -> "SHA256withRSA";
        case "RS384" -> "SHA384withRSA";
        case "RS512" -> "SHA512withRSA";
        // the raw R || S form of the JWS, not the DER form of the default
        case "ES256" -> "SHA256withECDSAinP1363Format";
        case "ES384" -> "SHA384withECDSAinP1363Format";
        case "ES512" -> "SHA512withECDSAinP1363Format";
        default -> null;
        };
    }

    private LogoutToken checkClaims(final Map<String, Object> claims, final String issuer, final String clientId, final long now) {
        if (!issuer.equals(claims.get("iss"))) {
            throw new LogoutTokenException("The logout token was not issued by the configured issuer.");
        }
        if (!hasAudience(claims.get("aud"), clientId)) {
            throw new LogoutTokenException("The logout token is not addressed to this client.");
        }
        if (!(claims.get("iat") instanceof final Number iat) || !(claims.get("exp") instanceof final Number exp)) {
            throw new LogoutTokenException("The logout token has no numeric iat and exp.");
        }
        // The negated forms also refuse NaN.
        if (!(iat.doubleValue() <= now + CLOCK_SKEW_SECONDS)) {
            throw new LogoutTokenException("The logout token was issued in the future.");
        }
        if (!(now < exp.doubleValue() + CLOCK_SKEW_SECONDS)) {
            throw new LogoutTokenException("The logout token has expired.");
        }
        if (!(now - iat.doubleValue() <= MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS)) {
            throw new LogoutTokenException("The logout token was issued too long ago.");
        }
        if (!(claims.get("jti") instanceof final String jti) || jti.isEmpty()) {
            throw new LogoutTokenException("The logout token has no jti.");
        }
        if (!(claims.get("events") instanceof final Map<?, ?> events) || !(events.get(BACKCHANNEL_LOGOUT_EVENT) instanceof Map)) {
            throw new LogoutTokenException("The logout token has no back-channel logout event.");
        }
        if (claims.containsKey("nonce")) {
            throw new LogoutTokenException("The logout token has a nonce, which an ID token has and a logout token must not.");
        }
        final String subject = claims.get("sub") instanceof final String sub && !sub.isEmpty() ? sub : null;
        final String sessionId = claims.get("sid") instanceof final String sid && !sid.isEmpty() ? sid : null;
        if (subject == null && sessionId == null) {
            throw new LogoutTokenException("The logout token has neither sub nor sid.");
        }
        return new LogoutToken((String) claims.get("iss"), subject, sessionId, jti, iat.longValue());
    }

    private static boolean hasAudience(final Object aud, final String clientId) {
        if (aud instanceof final String single) {
            return clientId.equals(single);
        }
        return aud instanceof final List<?> list && list.contains(clientId);
    }

    /**
     * The claims of a validated logout token that Fess uses.
     *
     * @param issuer the issuer
     * @param subject the {@code sub} claim, or null
     * @param sessionId the {@code sid} claim, or null
     * @param jti the token identifier
     * @param issuedAt the {@code iat} claim, in seconds since the epoch
     */
    public record LogoutToken(String issuer, String subject, String sessionId, String jti, long issuedAt) {
    }

    /**
     * Thrown when a logout token is not acceptable. The message names the failed check and holds nothing of the token.
     */
    public static class LogoutTokenException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        /**
         * Creates the exception.
         *
         * @param message the failed check
         */
        public LogoutTokenException(final String message) {
            super(message);
        }
    }
}
