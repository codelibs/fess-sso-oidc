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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codelibs.fesen.opensearch.OpenSearchException;
import org.codelibs.fesen.opensearch.action.DocWriteRequest.OpType;
import org.codelibs.fesen.opensearch.action.get.GetResponse;
import org.codelibs.fesen.opensearch.core.rest.RestStatus;
import org.codelibs.fess.util.ComponentUtil;

/**
 * Remembers, where every node of a Fess installation can read it, which identity provider sessions have been logged
 * out through back-channel logout and which logout tokens were used.
 *
 * <p>Both are small documents in the coordinator index ({@code fess_config.coordinator}), which Fess already uses for
 * the state that nodes share, whether or not the HTTP sessions themselves are shared. The index removes a document
 * once its {@code expiredTime} has passed. The documents have the fields that index maps ({@code type}, {@code name},
 * {@code createdTime}, {@code expiredTime}) and no others, so the mapping is not extended. A document id is the SHA-256
 * of what it stands for: the session id and the subject of the identity provider are not written to the index.</p>
 *
 * <ul>
 * <li>A <em>revocation</em> is keyed by the issuer and the {@code sid}, or by the issuer and the {@code sub}. Its
 * {@code createdTime} is when the logout was received. A session of the {@code sid} is over; a session of the
 * {@code sub} is over if it was opened no later than that time.</li>
 * <li>A <em>used token</em> is keyed by the issuer and the {@code jti}, and written with {@code op_type=create}, so
 * that of two nodes that receive the same token, one wins.</li>
 * </ul>
 *
 * <p>The methods throw a {@link RuntimeException} if the index cannot be read or written; what that means is for the caller.</p>
 */
public class LogoutRevocationStore {

    private static final Logger logger = LogManager.getLogger(LogoutRevocationStore.class);

    /** The index the documents are written to, with the default prefix. */
    protected static final String INDEX_NAME = "fess_config.coordinator";

    /** The {@code type} of a revocation. */
    protected static final String TYPE_REVOCATION = "oic_logout_revocation";

    /** The {@code type} of a used logout token. */
    protected static final String TYPE_USED_TOKEN = "oic_logout_token";

    /**
     * How long a revocation is kept. A session that is active meets it within the interval at which the revocations are
     * looked up, and an idle one is over after the idle timeout of the container, so a day is far beyond both.
     */
    protected static final long REVOCATION_TTL_MILLIS = 24 * 60 * 60 * 1000L;

    /**
     * How long a used token is kept: beyond the time a token is accepted at all
     * ({@value LogoutTokenValidator#MAX_AGE_SECONDS} seconds after {@code iat}, plus the clock skew), so a token that
     * is still acceptable is always found here.
     */
    protected static final long USED_TOKEN_TTL_MILLIS = 2 * 60 * 60 * 1000L;

    /**
     * Creates the store.
     */
    public LogoutRevocationStore() {
        // nothing to initialize: the search engine client is looked up for each call
    }

    /**
     * Makes the key of the revocation of one session of the identity provider.
     *
     * @param issuer the issuer
     * @param sessionId the {@code sid} claim
     * @return the key
     */
    public static String sessionKey(final String issuer, final String sessionId) {
        return digest("oic-sid", issuer, sessionId);
    }

    /**
     * Makes the key of the revocation of every session of a subject.
     *
     * @param issuer the issuer
     * @param subject the {@code sub} claim
     * @return the key
     */
    public static String subjectKey(final String issuer, final String subject) {
        return digest("oic-sub", issuer, subject);
    }

    /**
     * Makes the key of a logout token.
     *
     * @param issuer the issuer
     * @param jti the {@code jti} claim
     * @return the key
     */
    public static String tokenKey(final String issuer, final String jti) {
        return digest("oic-jti", issuer, jti);
    }

    private static String digest(final String kind, final String issuer, final String value) {
        try {
            // A length prefix, so that no two pairs of issuer and value make the same text.
            final String text = kind + '\n' + issuer.length() + '\n' + issuer + value;
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            // Every Java platform has to provide SHA-256.
            throw new IllegalStateException(e);
        }
    }

    /**
     * Remembers a logout token as used.
     *
     * @param key the key of the token
     * @param now the current time in milliseconds
     * @return false if the token was used before, true if this call is the first
     */
    public boolean markTokenUsed(final String key, final long now) {
        try {
            ComponentUtil.getSearchEngineClient()
                    .prepareIndex(getIndexName())
                    .setId(key)
                    .setOpType(OpType.CREATE)
                    .setSource(document(TYPE_USED_TOKEN, now, USED_TOKEN_TTL_MILLIS))
                    .execute()
                    .actionGet(ComponentUtil.getFessConfig().getIndexIndexTimeout());
            return true;
        } catch (final OpenSearchException e) {
            if (e.status() == RestStatus.CONFLICT) {
                return false;
            }
            throw e;
        }
    }

    /**
     * Forgets that a logout token was used, for a token whose logout could not be recorded and that the provider has
     * to be able to send again.
     *
     * @param key the key of the token
     */
    public void forgetToken(final String key) {
        ComponentUtil.getSearchEngineClient().delete(getIndexName(), key);
    }

    /**
     * Records a logout.
     *
     * @param key the key of the session or of the subject
     * @param now the time of the logout in milliseconds
     */
    public void revoke(final String key, final long now) {
        ComponentUtil.getSearchEngineClient()
                .prepareIndex(getIndexName())
                .setId(key)
                .setSource(document(TYPE_REVOCATION, now, REVOCATION_TTL_MILLIS))
                .execute()
                .actionGet(ComponentUtil.getFessConfig().getIndexIndexTimeout());
        if (logger.isDebugEnabled()) {
            logger.debug("Recorded a back-channel logout: key={}", key.substring(0, 12));
        }
    }

    /**
     * Looks up a logout. A get request is real-time, so a logout that another node just recorded is seen without
     * waiting for a refresh of the index.
     *
     * @param key the key of the session or of the subject
     * @param now the current time in milliseconds
     * @return the time of the logout in milliseconds, or -1 if none is recorded
     */
    public long findRevokedAt(final String key, final long now) {
        final GetResponse response = ComponentUtil.getSearchEngineClient()
                .prepareGet(getIndexName(), key)
                .execute()
                .actionGet(ComponentUtil.getFessConfig().getIndexSearchTimeout());
        if (!response.isExists()) {
            return -1;
        }
        final Map<String, Object> source = response.getSourceAsMap();
        if (source == null || !TYPE_REVOCATION.equals(source.get("type")) || !(source.get("createdTime") instanceof final Number created)
                || !(source.get("expiredTime") instanceof final Number expired) || expired.longValue() <= now) {
            return -1;
        }
        return created.longValue();
    }

    private static Map<String, Object> document(final String type, final long now, final long ttl) {
        final Map<String, Object> source = new HashMap<>();
        source.put("type", type);
        source.put("name", type);
        source.put("createdTime", now);
        source.put("expiredTime", now + ttl);
        return source;
    }

    /**
     * Returns the name of the coordinator index, adjusted for the configured index prefix.
     *
     * @return the index name
     */
    protected String getIndexName() {
        return INDEX_NAME.replaceFirst("fess_config", ComponentUtil.getFessConfig().getIndexConfigIndex());
    }
}
