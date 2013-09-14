/*
 * Copyright (c) 2010-2012 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package org.asynchttpclient.async;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Realm;
import org.asynchttpclient.Response;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.authentication.DigestAuthenticator;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public abstract class DigestAuthTest extends AbstractBasicTest {

    private static final String USER = "user";
    private static final String ADMIN = "admin";

    @BeforeClass(alwaysRun = true)
    @Override
    public void setUpGlobal() throws Exception {
        server = new Server();
        Logger root = Logger.getRootLogger();
        root.setLevel(Level.DEBUG);
        root.addAppender(new ConsoleAppender(new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN)));

        port1 = findFreePort();
        ServerConnector listener = new ServerConnector(server);

        listener.setHost("127.0.0.1");
        listener.setPort(port1);

        server.addConnector(listener);

        LoginService loginService = new HashLoginService("MyRealm", "src/test/resources/realm.properties");
        server.addBean(loginService);

        Constraint constraint = new Constraint();
        constraint.setName(Constraint.__BASIC_AUTH);
        constraint.setRoles(new String[] { USER, ADMIN });
        constraint.setAuthenticate(true);

        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setConstraint(constraint);
        mapping.setPathSpec("/*");

        List<ConstraintMapping> cm = new ArrayList<ConstraintMapping>();
        cm.add(mapping);

        Set<String> knownRoles = new HashSet<String>();
        knownRoles.add(USER);
        knownRoles.add(ADMIN);

        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        security.setConstraintMappings(cm, knownRoles);
        security.setAuthenticator(new DigestAuthenticator());
        security.setLoginService(loginService);
        security.setStrict(false);

        security.setHandler(configureHandler());
        server.setHandler(security);
        server.start();
        log.info("Local HTTP server started successfully");
    }

    private class SimpleHandler extends AbstractHandler {
        public void handle(String s, Request r, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {

            response.addHeader("X-Auth", request.getHeader("Authorization"));
            response.setStatus(200);
            response.getOutputStream().flush();
            response.getOutputStream().close();
        }
    }

    @Test(groups = { "standalone", "default_provider" })
    public void digestAuthTest() throws IOException, ExecutionException, TimeoutException, InterruptedException {
        AsyncHttpClient client = getAsyncHttpClient(null);
        try {
            AsyncHttpClient.BoundRequestBuilder r = client.prepareGet("http://127.0.0.1:" + port1 + "/").setRealm((new Realm.RealmBuilder()).setPrincipal(USER).setPassword(ADMIN).setRealmName("MyRealm").setScheme(Realm.AuthScheme.DIGEST).build());

            Future<Response> f = r.execute();
            Response resp = f.get(60, TimeUnit.SECONDS);
            assertNotNull(resp);
            assertEquals(resp.getStatusCode(), HttpServletResponse.SC_OK);
            assertNotNull(resp.getHeader("X-Auth"));
        } finally {
            client.close();
        }
    }

    @Test(groups = { "standalone", "default_provider" })
    public void digestAuthTestWithoutScheme() throws IOException, ExecutionException, TimeoutException, InterruptedException {
        AsyncHttpClient client = getAsyncHttpClient(null);
        try {
            AsyncHttpClient.BoundRequestBuilder r = client.prepareGet("http://127.0.0.1:" + port1 + "/").setRealm((new Realm.RealmBuilder()).setPrincipal(USER).setPassword(ADMIN).setRealmName("MyRealm").build());

            Future<Response> f = r.execute();
            Response resp = f.get(60, TimeUnit.SECONDS);
            assertNotNull(resp);
            assertEquals(resp.getStatusCode(), HttpServletResponse.SC_OK);
            assertNotNull(resp.getHeader("X-Auth"));
        } finally {
            client.close();
        }
    }

    @Test(groups = { "standalone", "default_provider" })
    public void digestAuthNegativeTest() throws IOException, ExecutionException, TimeoutException, InterruptedException {
        AsyncHttpClient client = getAsyncHttpClient(null);
        try {
            AsyncHttpClient.BoundRequestBuilder r = client.prepareGet("http://127.0.0.1:" + port1 + "/").setRealm((new Realm.RealmBuilder()).setPrincipal("fake").setPassword(ADMIN).setScheme(Realm.AuthScheme.DIGEST).build());

            Future<Response> f = r.execute();
            Response resp = f.get(20, TimeUnit.SECONDS);
            assertNotNull(resp);
            assertEquals(resp.getStatusCode(), 401);
        } finally {
            client.close();
        }
    }

    @Override
    public AbstractHandler configureHandler() throws Exception {
        return new SimpleHandler();
    }
}
