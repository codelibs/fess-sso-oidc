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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

import org.codelibs.fess.mylasta.action.FessUserBean;
import org.codelibs.fess.session.SessionDataSerializer;
import org.codelibs.fess.sso.oic.OpenIdConnectCredential.OpenIdUser;
import org.junit.jupiter.api.Test;
import org.lastaflute.di.core.SingletonLaContainer;
import org.lastaflute.di.core.factory.SingletonLaContainerFactory;
import org.lastaflute.di.core.external.GenericExternalContext;
import org.lastaflute.di.core.external.GenericExternalContextComponentDefRegister;

/**
 * Starts the container with the DI files of Fess and of this plugin that matter to the session store, as the
 * web application does, and checks the serializer of the store afterwards. The unit tests of this plugin
 * run in a container that has neither file, so they say nothing about the registration.
 */
public class OpenIdConnectContainerTest {

    @Test
    public void test_theUserIsRegisteredWithTheSessionStoreWhenTheContainerStarts() {
        // a container that another test class left behind would be kept by init()
        SingletonLaContainerFactory.destroy();
        SingletonLaContainerFactory.setConfigPath("probe_app.xml");
        SingletonLaContainerFactory.setExternalContext(new GenericExternalContext());
        SingletonLaContainerFactory.setExternalContextComponentDefRegister(new GenericExternalContextComponentDefRegister());
        SingletonLaContainerFactory.init();
        try {
            // Not looked up: the authenticator is not asked for here, so only the start of the container
            // can have registered the class. The registrations are fixed by the first use of the serializer.
            final SessionDataSerializer serializer = SingletonLaContainer.getComponent("sessionDataSerializer");
            assertNotEquals(new SessionDataSerializer().getFormatVersion(), serializer.getFormatVersion());

            final Map<String, Object> attributes = new LinkedHashMap<>();
            attributes.put("userBean", new FessUserBean(new OpenIdUser("taro@example.com", new String[] { "dev" }, new String[0])));
            final TreeSet<String> skipped = new TreeSet<>();
            final byte[] bytes = serializer.toBytes(attributes, skipped);

            assertTrue(skipped.isEmpty(), "skipped: " + skipped);
            final FessUserBean restored = (FessUserBean) serializer.fromBytes(bytes).get("userBean");
            assertNotNull(restored);
            assertEquals("taro@example.com", restored.getUserId());
            assertTrue(restored.getFessUser() instanceof OpenIdUser);

            // one definition of the authenticator: a second one would make the lookup fail
            assertNotNull(SingletonLaContainer.getComponent("oicAuthenticator"));
        } finally {
            SingletonLaContainerFactory.destroy();
        }
    }
}
