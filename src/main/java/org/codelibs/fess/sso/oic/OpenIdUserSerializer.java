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

import org.codelibs.core.lang.StringUtil;
import org.codelibs.fess.sso.oic.OpenIdConnectCredential.OpenIdUser;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.KryoException;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

/**
 * Writes an {@link OpenIdUser} for the OpenSearch-backed session store, so that a user who logged in
 * through OpenID Connect on one node is logged in on the others.
 *
 * <p>Only what authorization reads is written: the user name, the group names and the role names. The
 * permissions are not written, because {@link OpenIdUser#getPermissions()} derives them from those three
 * when they are first asked for, so a restored user can never hold a permission the names do not give.
 * Nothing of the token response is part of the user, so no ID token, access token or refresh token is
 * written, and nothing reads one after a login.</p>
 *
 * <p>Every length is checked against a fixed bound and against the bytes left before anything is
 * allocated, and a value that violates a bound is refused with a {@link KryoException}, so that the
 * session attribute is dropped and the user has to log in again. Strings are written as a length and UTF-8
 * bytes instead of with the string encoding of Kryo, so that this class, and not the encoding, decides how
 * long a name may be.</p>
 */
public class OpenIdUserSerializer extends Serializer<OpenIdUser> {

    /** The number of the layout written. Change it with the layout; an older layout is refused. */
    protected static final int LAYOUT = 1;

    /** The most group names, or role names, that are written or read. */
    protected static final int MAX_ENTRIES = 10_000;

    /** The longest user name, group name or role name in UTF-8 bytes. */
    protected static final int MAX_TEXT_BYTES = 4096;

    /**
     * Creates the serializer.
     */
    public OpenIdUserSerializer() {
        // the serializer keeps no state, as it is shared by all threads
    }

    @Override
    public void write(final Kryo kryo, final Output output, final OpenIdUser user) {
        if (StringUtil.isBlank(user.getName())) {
            throw new KryoException("The OpenID Connect user has no name.");
        }
        output.writeVarInt(LAYOUT, true);
        writeText(output, user.getName());
        writeTexts(output, user.getGroupNames());
        writeTexts(output, user.getRoleNames());
    }

    @Override
    public OpenIdUser read(final Kryo kryo, final Input input, final Class<? extends OpenIdUser> type) {
        final int layout = input.readVarInt(true);
        if (layout != LAYOUT) {
            throw new KryoException("The layout of the OpenID Connect user is not supported: " + layout);
        }
        final String name = readText(input);
        if (StringUtil.isBlank(name)) {
            throw new KryoException("The OpenID Connect user has no name.");
        }
        final String[] groups = readTexts(input);
        final String[] roles = readTexts(input);
        return new OpenIdUser(name, groups, roles);
    }

    /**
     * Writes a text as the length of its UTF-8 bytes and the bytes.
     *
     * @param output the output
     * @param text the text, not null
     */
    protected static void writeText(final Output output, final String text) {
        final byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_TEXT_BYTES) {
            throw new KryoException("The text is too long to be stored: " + bytes.length + " bytes");
        }
        output.writeVarInt(bytes.length, true);
        output.writeBytes(bytes);
    }

    /**
     * Reads a text written by {@link #writeText(Output, String)}.
     *
     * @param input the input
     * @return the text
     */
    protected static String readText(final Input input) {
        final int length = input.readVarInt(true);
        if (length < 0 || length > MAX_TEXT_BYTES || length > input.limit() - input.position()) {
            throw new KryoException("The length of a text is invalid: " + length);
        }
        return new String(input.readBytes(length), StandardCharsets.UTF_8);
    }

    /**
     * Writes names that may be absent: zero for none, otherwise the number of names plus one.
     *
     * @param output the output
     * @param texts the names, or null
     */
    protected static void writeTexts(final Output output, final String[] texts) {
        if (texts == null) {
            output.writeVarInt(0, true);
            return;
        }
        if (texts.length > MAX_ENTRIES) {
            throw new KryoException("Too many names to be stored: " + texts.length);
        }
        output.writeVarInt(texts.length + 1, true);
        for (final String text : texts) {
            if (text == null) {
                throw new KryoException("A name is null.");
            }
            writeText(output, text);
        }
    }

    /**
     * Reads names written by {@link #writeTexts(Output, String[])}.
     *
     * @param input the input
     * @return the names, or null
     */
    protected static String[] readTexts(final Input input) {
        final int marker = input.readVarInt(true);
        if (marker == 0) {
            return null;
        }
        final int count = marker - 1;
        // every name takes at least one byte, so a count beyond the bytes left cannot be true
        if (count < 0 || count > MAX_ENTRIES || count > input.limit() - input.position()) {
            throw new KryoException("The number of names is invalid: " + count);
        }
        final String[] texts = new String[count];
        for (int i = 0; i < count; i++) {
            texts[i] = readText(input);
        }
        return texts;
    }
}
