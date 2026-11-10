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
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

import org.codelibs.fess.helper.SystemHelper;
import org.codelibs.fess.mylasta.action.FessUserBean;
import org.codelibs.fess.session.SessionDataSerializer;
import org.codelibs.fess.sso.oic.OpenIdConnectCredential.OpenIdUser;
import org.codelibs.fess.unit.UnitFessTestCase;
import org.codelibs.fess.util.ComponentUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.KryoException;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

/**
 * Tests that the user of an OpenID Connect login is stored for the session store as authorization needs
 * it and not more, and that a damaged stored value cannot be read as a user.
 */
public class OpenIdUserSerializerTest extends UnitFessTestCase {

    private static final String USER_BEAN = "userBean";

    private static final String EMAIL = "taro.yamada@example.com";

    private SessionDataSerializer serializer;

    @Override
    protected void setUp(final TestInfo testInfo) throws Exception {
        super.setUp(testInfo);
        // the search roles are the prefix and the name, which is all the test needs of them
        ComponentUtil.register(new SystemHelper() {
            @Override
            public String getSearchRoleByDirectoryUser(final String name) {
                return "U" + name;
            }

            @Override
            public String getSearchRoleByDirectoryGroup(final String name) {
                return "G" + name;
            }

            @Override
            public String getSearchRoleByDirectoryRole(final String name) {
                return "R" + name;
            }
        }, "systemHelper");
        serializer = newSerializer();
    }

    private static SessionDataSerializer newSerializer() {
        final SessionDataSerializer serializer = new SessionDataSerializer();
        serializer.register(OpenIdUser.class, new OpenIdUserSerializer());
        return serializer;
    }

    private static OpenIdUser user(final String name, final String[] groups, final String[] roles) {
        return new OpenIdUser(name, groups, roles);
    }

    private static Map<String, Object> attributes(final Object bean) {
        final Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put(USER_BEAN, bean);
        attributes.put("sibling", "kept");
        return attributes;
    }

    private static boolean contains(final byte[] bytes, final String text) {
        final byte[] needle = text.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i + needle.length <= bytes.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(bytes, i, i + needle.length), needle)) {
                return true;
            }
        }
        return false;
    }

    // ===================================================================================
    //                                                                          Round trip
    //                                                                          ==========
    @Test
    public void test_roundTrip() {
        final FessUserBean bean = new FessUserBean(user(EMAIL, new String[] { "dev", "日本語グループ" }, new String[] { "admin" }));
        bean.setLoginTime(1234L);
        final TreeSet<String> skipped = new TreeSet<>();

        final byte[] bytes = serializer.toBytes(attributes(bean), skipped);
        final Map<String, Object> restored = serializer.fromBytes(bytes);

        assertTrue(skipped.isEmpty());
        assertEquals("kept", restored.get("sibling"));
        final FessUserBean restoredBean = (FessUserBean) restored.get(USER_BEAN);
        assertEquals(1234L, restoredBean.getLoginTime());
        assertTrue(restoredBean.getFessUser() instanceof OpenIdUser);
        assertEquals(EMAIL, restoredBean.getUserId());
        assertEquals(Arrays.asList("dev", "日本語グループ"), Arrays.asList(restoredBean.getGroups()));
        assertEquals(Arrays.asList("admin"), Arrays.asList(restoredBean.getRoles()));
        assertTrue(restoredBean.hasRole("admin"));
        assertTrue(restoredBean.hasGroup("dev"));
        assertFalse(restoredBean.hasRole("dev"));
        // the permissions are the ones the names give on the node that restores the user
        assertEquals(Arrays.asList(user(EMAIL, restoredBean.getGroups(), restoredBean.getRoles()).getPermissions()),
                Arrays.asList(restoredBean.getPermissions()));
        assertEquals(new TreeSet<>(Arrays.asList("U" + EMAIL, "Gdev", "G日本語グループ", "Radmin")),
                new TreeSet<>(Arrays.asList(restoredBean.getPermissions())));
    }

    @Test
    public void test_roundTrip_emptyAndAbsentNames() {
        final OpenIdUser empty = (OpenIdUser) roundTrip(user(EMAIL, new String[0], new String[0]));
        assertEquals(0, empty.getGroupNames().length);
        assertEquals(0, empty.getRoleNames().length);

        final OpenIdUser absent = (OpenIdUser) roundTrip(user(EMAIL, null, null));
        assertNull(absent.getGroupNames());
        assertNull(absent.getRoleNames());
    }

    private Object roundTrip(final OpenIdUser user) {
        final Map<String, Object> restored = serializer.fromBytes(serializer.toBytes(attributes(new FessUserBean(user))));
        return ((FessUserBean) restored.get(USER_BEAN)).getFessUser();
    }

    @Test
    public void test_aUserOfAnotherNodeWithoutThePluginIsNotReadAsAUser() {
        // a node without the plugin has another format version, so what the plugin node wrote is not read at all
        final byte[] bytes = serializer.toBytes(attributes(new FessUserBean(user(EMAIL, new String[0], new String[0]))));

        assertNull(new SessionDataSerializer().fromBytes(bytes));
    }

    @Test
    public void test_withoutRegistrationTheUserStaysOnTheNode() {
        final TreeSet<String> skipped = new TreeSet<>();

        final byte[] bytes =
                new SessionDataSerializer().toBytes(attributes(new FessUserBean(user(EMAIL, new String[0], new String[0]))), skipped);

        assertTrue(skipped.contains(USER_BEAN));
        assertFalse(contains(bytes, EMAIL));
    }

    // ===================================================================================
    //                                                                 What is not written
    //                                                                 ===================
    @Test
    public void test_theTokensOfTheLoginAreNotInTheBytes() {
        // The credential holds the tokens of the login; the user made from it must not carry any of them.
        final Map<String, Object> claims = new HashMap<>();
        claims.put("email", EMAIL);
        claims.put("groups", java.util.List.of("dev"));
        claims.put("accesstoken", "ACCESS-TOKEN-MARKER");
        claims.put("refreshtoken", "REFRESH-TOKEN-MARKER");
        claims.put("jwtheader", "JWT-HEADER-MARKER");
        claims.put("jwtclaim", "JWT-CLAIM-MARKER");
        claims.put("jwtsignature", "JWT-SIGNATURE-MARKER");
        claims.put("id_token", "ID-TOKEN-MARKER");
        claims.put("sub", "SUBJECT-MARKER");

        final byte[] bytes = serializer.toBytes(attributes(new FessUserBean(new OpenIdConnectCredential(claims).getUser())));

        // the control: the search cannot pass because it never matches
        assertTrue(contains(bytes, EMAIL));
        assertTrue(contains(bytes, "dev"));
        for (final String marker : new String[] { "ACCESS-TOKEN-MARKER", "REFRESH-TOKEN-MARKER", "JWT-HEADER-MARKER", "JWT-CLAIM-MARKER",
                "JWT-SIGNATURE-MARKER", "ID-TOKEN-MARKER", "SUBJECT-MARKER" }) {
            assertFalse(contains(bytes, marker), marker);
        }
    }

    @Test
    public void test_thePermissionsAreNotStoredButDerivedAgain() {
        final OpenIdUser user = user(EMAIL, new String[] { "dev" }, new String[0]);
        assertEquals(new TreeSet<>(Arrays.asList("U" + EMAIL, "Gdev")), new TreeSet<>(Arrays.asList(user.getPermissions())));
        // a permission the names do not give, put where the lazily computed value is kept
        user.permissions = new String[] { "Rsuperuser" };
        assertEquals("Rsuperuser", user.getPermissions()[0]);

        final byte[] bytes = serializer.toBytes(attributes(new FessUserBean(user)));
        final OpenIdUser restored = (OpenIdUser) ((FessUserBean) serializer.fromBytes(bytes).get(USER_BEAN)).getFessUser();

        assertFalse(contains(bytes, "Rsuperuser"));
        assertEquals(new TreeSet<>(Arrays.asList("U" + EMAIL, "Gdev")), new TreeSet<>(Arrays.asList(restored.getPermissions())));
    }

    @Test
    public void test_aUserWithoutANameIsNotStored() {
        for (final String name : new String[] { null, "", "  " }) {
            final TreeSet<String> skipped = new TreeSet<>();
            final byte[] bytes = serializer.toBytes(attributes(new FessUserBean(user(name, new String[0], new String[0]))), skipped);
            assertTrue(skipped.contains(USER_BEAN), String.valueOf(name));
            assertNull(serializer.fromBytes(bytes).get(USER_BEAN));
        }
    }

    @Test
    public void test_aUserThatCannotBeReadBackIsNotStored() {
        final String[] many = new String[OpenIdUserSerializer.MAX_ENTRIES + 1];
        Arrays.fill(many, "g");
        final String[] withNull = { "g", null };
        final String longName = "x".repeat(OpenIdUserSerializer.MAX_TEXT_BYTES + 1);

        for (final OpenIdUser user : new OpenIdUser[] { user(EMAIL, many, new String[0]), user(EMAIL, withNull, new String[0]),
                user(EMAIL, new String[0], withNull), user(longName, new String[0], new String[0]),
                user(EMAIL, new String[] { longName }, new String[0]) }) {
            final TreeSet<String> skipped = new TreeSet<>();
            serializer.toBytes(attributes(new FessUserBean(user)), skipped);
            assertTrue(skipped.contains(USER_BEAN));
        }
    }

    // ===================================================================================
    //                                                                           Hardening
    //                                                                           =========
    @Test
    public void test_everyTruncationIsRefusedWithoutAnError() {
        final byte[] bytes =
                serializer.toBytes(attributes(new FessUserBean(user(EMAIL, new String[] { "dev", "ops" }, new String[] { "admin" }))));

        for (int length = 0; length < bytes.length; length++) {
            final Map<String, Object> restored = serializer.fromBytes(Arrays.copyOf(bytes, length));
            if (restored != null) {
                assertFalse(restored.get(USER_BEAN) instanceof FessUserBean, "length " + length);
            }
        }
        assertNotNull(serializer.fromBytes(bytes).get(USER_BEAN));
    }

    @Test
    public void test_garbageIsRefusedWithoutAnError() {
        final java.util.Random random = new java.util.Random(7);
        final byte[] valid = serializer.toBytes(attributes(new FessUserBean(user(EMAIL, new String[] { "dev" }, new String[0]))));
        for (int i = 0; i < 2000; i++) {
            final byte[] garbage = new byte[random.nextInt(64)];
            random.nextBytes(garbage);
            serializer.fromBytes(garbage);
            // the same, behind a valid header, so that the value is the part that is damaged
            final byte[] damaged = valid.clone();
            for (int j = 0; j < 3; j++) {
                damaged[random.nextInt(damaged.length)] = (byte) random.nextInt(256);
            }
            final Map<String, Object> restored = serializer.fromBytes(damaged);
            if (restored != null && restored.get(USER_BEAN) instanceof final FessUserBean bean) {
                // a damaged name or group may still be a name, but never a user of no name
                assertTrue(bean.getUserId() != null && !bean.getUserId().isBlank());
            }
        }
    }

    @Test
    public void test_aDamagedUserDropsOnlyItsOwnAttribute() {
        final byte[] bytes = serializer.toBytes(attributes(new FessUserBean(user(EMAIL, new String[] { "dev" }, new String[0]))));

        // the control: the same replacement with the bytes of a valid user restores the user, so that the
        // refusals below are the refusals of the bytes and not of the way they were put in
        final Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(true);
        kryo.register(OpenIdUser.class, new OpenIdUserSerializer());
        final Output valid = new Output(64, -1);
        kryo.writeObject(valid, user("other@example.com", new String[] { "x" }, new String[0]));
        final FessUserBean control = (FessUserBean) serializer.fromBytes(replaceUser(bytes, valid.toBytes())).get(USER_BEAN);
        assertEquals("other@example.com", control.getUserId());

        // oversized count of group names: the layout, a name, then 2^31-1 names
        final Output tail = new Output(64, -1);
        tail.writeVarInt(OpenIdUserSerializer.LAYOUT, true);
        tail.writeVarInt(1, true);
        tail.writeByte('a');
        tail.writeVarInt(Integer.MAX_VALUE, true);
        assertUserDropped(bytes, tail.toBytes());

        // oversized length of the name
        final Output name = new Output(64, -1);
        name.writeVarInt(OpenIdUserSerializer.LAYOUT, true);
        name.writeVarInt(Integer.MAX_VALUE, true);
        assertUserDropped(bytes, name.toBytes());

        // a length that the bytes cannot have
        final Output beyond = new Output(64, -1);
        beyond.writeVarInt(OpenIdUserSerializer.LAYOUT, true);
        beyond.writeVarInt(50, true);
        beyond.writeBytes(new byte[] { 'a', 'b' });
        assertUserDropped(bytes, beyond.toBytes());

        // another layout, and no name
        assertUserDropped(bytes, new byte[] { 9, 1, 'a', 0, 0 });
        assertUserDropped(bytes, new byte[] { OpenIdUserSerializer.LAYOUT, 0, 0, 0 });
        assertUserDropped(bytes, new byte[] { OpenIdUserSerializer.LAYOUT, 1, ' ', 0, 0 });
    }

    /** Replaces the part of the stored bean that the serializer of the user reads, and expects the bean to be dropped. */
    private void assertUserDropped(final byte[] valid, final byte[] userBytes) {
        final byte[] replaced = replaceUser(valid, userBytes);
        final Map<String, Object> restored = serializer.fromBytes(replaced);
        assertNotNull(restored);
        assertNull(restored.get(USER_BEAN));
        assertEquals("kept", restored.get("sibling"));
    }

    /**
     * Rebuilds the stored attributes with the bytes that the serializer of the user reads replaced. The bytes of a
     * bean are the class id of the bean, the class id of the user and the bytes of the user, then the fields of the bean.
     */
    private byte[] replaceUser(final byte[] valid, final byte[] userBytes) {
        final Input input = new Input(valid);
        final Output output = new Output(256, -1);
        output.writeVarInt(input.readVarInt(true), true);
        output.writeLong(input.readLong());
        final int count = input.readVarInt(true);
        output.writeVarInt(count, true);
        for (int i = 0; i < count; i++) {
            final String name = input.readString();
            byte[] value = input.readBytes(input.readVarInt(true));
            if (USER_BEAN.equals(name)) {
                final Input v = new Input(value);
                final Output w = new Output(256, -1);
                w.writeVarInt(v.readVarInt(true), true); // the class id of the bean
                w.writeVarInt(v.readVarInt(true), true); // the class id of the user
                v.skip(lengthOfUser(v));
                w.writeBytes(userBytes);
                w.writeBytes(v.readBytes(v.limit() - v.position()));
                value = w.toBytes();
            }
            output.writeString(name);
            output.writeVarInt(value.length, true);
            output.writeBytes(value);
        }
        return output.toBytes();
    }

    /** Measures the bytes of a user at the position of an input, and leaves the position where it was. */
    private static int lengthOfUser(final Input input) {
        final int start = input.position();
        final Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(true);
        kryo.register(OpenIdUser.class, new OpenIdUserSerializer());
        kryo.readObject(input, OpenIdUser.class);
        final int length = input.position() - start;
        input.setPosition(start);
        return length;
    }

    @Test
    public void test_aDamagedUserIsRefusedWithKryoException() {
        final Kryo kryo = new Kryo();
        kryo.setRegistrationRequired(true);
        kryo.register(OpenIdUser.class, new OpenIdUserSerializer());

        final Output oversized = new Output(32, -1);
        oversized.writeVarInt(OpenIdUserSerializer.LAYOUT, true);
        oversized.writeVarInt(3, true);
        oversized.writeBytes(new byte[] { 'a', 'b', 'c' });
        oversized.writeVarInt(Integer.MAX_VALUE, true);
        try {
            kryo.readObject(new Input(oversized.toBytes()), OpenIdUser.class);
            fail("an oversized count of names was read");
        } catch (final KryoException e) {
            // refused before an array of that size is made
        }
    }

    @Test
    public void test_anUnregisteredClassIdIsRefused() {
        final byte[] bytes = serializer.toBytes(attributes(new FessUserBean(user(EMAIL, new String[0], new String[0]))));
        final Input input = new Input(bytes);
        final Output output = new Output(256, -1);
        output.writeVarInt(input.readVarInt(true), true);
        output.writeLong(input.readLong());
        final int count = input.readVarInt(true);
        output.writeVarInt(count, true);
        for (int i = 0; i < count; i++) {
            final String name = input.readString();
            byte[] value = input.readBytes(input.readVarInt(true));
            if (USER_BEAN.equals(name)) {
                // an id that no class has: Kryo has no class to create for it
                final Output unknown = new Output(16, -1);
                unknown.writeVarInt(10_000, true);
                unknown.writeBytes(new byte[] { 1, 2, 3 });
                value = unknown.toBytes();
            }
            output.writeString(name);
            output.writeVarInt(value.length, true);
            output.writeBytes(value);
        }

        final Map<String, Object> restored = serializer.fromBytes(output.toBytes());

        assertNotNull(restored);
        assertNull(restored.get(USER_BEAN));
        assertEquals("kept", restored.get("sibling"));
    }

    @Test
    public void test_theOnlyThingStoredAsAUserIsTheClassRegistered() {
        // a user class that was not registered is a class Kryo has no id for, so it is not written either
        final OpenIdUser subclass = new OpenIdUser(EMAIL, new String[0], new String[0]) {
            private static final long serialVersionUID = 1L;
        };
        final TreeSet<String> skipped = new TreeSet<>();

        serializer.toBytes(attributes(new FessUserBean(subclass)), skipped);

        assertTrue(skipped.contains(USER_BEAN));
    }
}
