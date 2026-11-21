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

import static org.codelibs.core.stream.StreamUtil.split;
import static org.codelibs.core.stream.StreamUtil.stream;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.codelibs.core.lang.StringUtil;
import org.codelibs.fess.app.web.base.login.FessCredential;
import org.codelibs.fess.entity.FessUser;
import org.codelibs.fess.helper.SystemHelper;
import org.codelibs.fess.util.ComponentUtil;
import org.codelibs.fess.util.DocumentUtil;
import org.lastaflute.web.login.credential.LoginCredential;

/**
 * OpenID Connect credential implementation.
 */
public class OpenIdConnectCredential implements LoginCredential, FessCredential {

    private final Map<String, Object> attributes;

    /**
     * Creates a new OpenID Connect credential.
     *
     * @param attributes the attributes from OpenID Connect provider
     */
    public OpenIdConnectCredential(final Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String toString() {
        return "{" + getUserId() + "}";
    }

    @Override
    public String getUserId() {
        // Not DocumentUtil.getValue: it turns a list into its first element and a number into its text, so a
        // claim that is not an address would become the user name.
        return attributes.get("email") instanceof final String email ? email : null;
    }

    /**
     * Gets the user groups.
     *
     * @return the user groups
     */
    public String[] getUserGroups() {
        if (attributes.get("groups") instanceof final String singleGroup) {
            // A provider that collapses a single-valued claim to a bare JSON string still named a
            // group. DocumentUtil answers null when a String is asked for as a String[], which is the
            // same answer it gives for a claim that was never sent, so this used to be indistinguishable
            // from an absent claim and the user silently got oic.default.groups instead of their own
            // group. An empty value is treated like an empty array: the claim was sent, so the default
            // does not apply.
            return StringUtil.isBlank(singleGroup) ? StringUtil.EMPTY_STRINGS : new String[] { singleGroup.trim() };
        }
        String[] userGroups = DocumentUtil.getValue(attributes, "groups", String[].class);
        if (userGroups == null) {
            userGroups = getDefaultGroupsAsArray();
        }
        return userGroups;
    }

    /**
     * Gets the OpenID Connect user.
     *
     * @return the OpenID Connect user
     */
    public OpenIdUser getUser() {
        return new OpenIdUser(getUserId(), getUserGroups(), getDefaultRolesAsArray(), identifier("iss"), identifier("sub"),
                identifier("sid"), System.currentTimeMillis());
    }

    /**
     * Reads a claim that identifies the login at the provider: the issuer, the subject or the session id. These are
     * what a back-channel logout names, and are kept with the login to be found by it.
     *
     * @param name the claim
     * @return the claim, or null if it is not a non-empty string of at most {@value OpenIdUser#MAX_IDENTIFIER_LENGTH}
     *         characters. A longer one is no identifier any provider issues, and is left out so that it cannot make
     *         the session impossible to store.
     */
    protected String identifier(final String name) {
        return attributes.get(name) instanceof final String value && !value.isEmpty() && value.length() <= OpenIdUser.MAX_IDENTIFIER_LENGTH
                ? value
                : null;
    }

    /**
     * Gets the default groups as an array.
     *
     * @return the default groups
     */
    protected static String[] getDefaultGroupsAsArray() {
        final String value = ComponentUtil.getFessConfig().getSystemProperty("oic.default.groups");
        if (StringUtil.isBlank(value)) {
            return StringUtil.EMPTY_STRINGS;
        }
        return split(value, ",").get(stream -> stream.filter(StringUtil::isNotBlank).map(String::trim).toArray(n -> new String[n]));
    }

    /**
     * Gets the default roles as an array.
     *
     * @return the default roles
     */
    protected static String[] getDefaultRolesAsArray() {
        final String value = ComponentUtil.getFessConfig().getSystemProperty("oic.default.roles");
        if (StringUtil.isBlank(value)) {
            return StringUtil.EMPTY_STRINGS;
        }
        return split(value, ",").get(stream -> stream.filter(StringUtil::isNotBlank).map(String::trim).toArray(n -> new String[n]));
    }

    /**
     * OpenID Connect user implementation.
     */
    public static class OpenIdUser implements FessUser {

        private static final long serialVersionUID = 1L;

        /** The user name. */
        protected final String name;

        /** The user groups. */
        protected String[] groups;

        /** The user roles. */
        protected String[] roles;

        /** The longest issuer, subject or session id kept with the login, in characters. */
        public static final int MAX_IDENTIFIER_LENGTH = 1024;

        /** The issuer of the ID token that opened this login, or null if it is not known. */
        protected final String issuer;

        /** The {@code sub} of the ID token, or null if it is not known. */
        protected final String subject;

        /** The {@code sid} of the ID token, which names the session at the provider, or null if the token has none. */
        protected final String sessionId;

        /** The time this login was opened, in epoch milliseconds, or 0 if it is not known. */
        protected final long loginTime;

        /**
         * The user permissions.
         *
         * <p>Lazily computed by {@link #getPermissions()} and never invalidated afterwards.
         * {@code volatile} for the same reason as in {@code SamlCredential.SamlUser}, the
         * equivalent class in the fess-sso-saml plugin (not linked, because it is in neither this
         * jar nor Fess): the enclosing bean is a session attribute shared by concurrent requests,
         * and the array is written after the session publication, so an unsynchronized reader could
         * see the reference before the elements.</p>
         */
        protected volatile String[] permissions;

        /**
         * Creates a new OpenID Connect user.
         *
         * @param name the user name
         * @param groups the user groups
         * @param roles the user roles
         */
        protected OpenIdUser(final String name, final String[] groups, final String[] roles) {
            this(name, groups, roles, null, null, null, 0L);
        }

        /**
         * Creates a new OpenID Connect user that a back-channel logout can find.
         *
         * @param name the user name
         * @param groups the user groups
         * @param roles the user roles
         * @param issuer the issuer of the ID token, or null
         * @param subject the {@code sub} of the ID token, or null
         * @param sessionId the {@code sid} of the ID token, or null
         * @param loginTime the time the login was opened, in epoch milliseconds, or 0
         */
        protected OpenIdUser(final String name, final String[] groups, final String[] roles, final String issuer, final String subject,
                final String sessionId, final long loginTime) {
            this.name = name;
            this.groups = groups;
            this.roles = roles;
            this.issuer = issuer;
            this.subject = subject;
            this.sessionId = sessionId;
            this.loginTime = loginTime;
        }

        /**
         * Gets the issuer of the ID token that opened this login.
         *
         * @return the issuer, or null
         */
        public String getIssuer() {
            return issuer;
        }

        /**
         * Gets the {@code sub} of the ID token that opened this login.
         *
         * @return the subject, or null
         */
        public String getSubject() {
            return subject;
        }

        /**
         * Gets the {@code sid} of the ID token that opened this login.
         *
         * @return the session id at the provider, or null
         */
        public String getSessionId() {
            return sessionId;
        }

        /**
         * Gets the time this login was opened.
         *
         * @return the time in epoch milliseconds, or 0 if it is not known
         */
        public long getLoginTime() {
            return loginTime;
        }

        /**
         * Tells whether the provider has logged this login out through back-channel logout, which ends the session
         * here the next time it is looked at. Without {@code oic.jwks.uri} the provider cannot be heard, and this is
         * always false.
         *
         * <p>Not marked {@code @Override}, like the same method of the SAML plugin: a Fess before 15.10 has no such method
         * to override, and then this is never called.</p>
         *
         * @return true if the login has ended at the provider
         */
        public boolean isExpired() {
            if (subject == null && sessionId == null || !ComponentUtil.hasComponent(OpenIdConnectAuthenticator.COMPONENT_NAME)) {
                return false;
            }
            return ComponentUtil.<OpenIdConnectAuthenticator> getComponent(OpenIdConnectAuthenticator.COMPONENT_NAME).isLoginRevoked(this);
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String[] getRoleNames() {
            return roles;
        }

        @Override
        public String[] getGroupNames() {
            return groups;
        }

        @Override
        public String[] getPermissions() {
            if (permissions == null) {
                final SystemHelper systemHelper = ComponentUtil.getSystemHelper();
                final Set<String> permissionSet = new HashSet<>();
                permissionSet.add(systemHelper.getSearchRoleByDirectoryUser(name));
                stream(groups).of(stream -> stream.forEach(s -> permissionSet.add(systemHelper.getSearchRoleByDirectoryGroup(s))));
                stream(roles).of(stream -> stream.forEach(s -> permissionSet.add(systemHelper.getSearchRoleByDirectoryRole(s))));
                permissions = permissionSet.toArray(new String[permissionSet.size()]);
            }
            return permissions;
        }

    }
}
