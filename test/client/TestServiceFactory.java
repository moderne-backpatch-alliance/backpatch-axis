/*
 * Copyright 2026 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package test.client;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.axis.client.Service;
import org.apache.axis.client.ServiceFactory;

import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.OperationNotSupportedException;
import javax.naming.spi.InitialContextFactory;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

/**
 * ServiceFactory.getService must refuse JNDI names naming a remote lookup mechanism
 * before it hands them to the context. The context here is in memory and records lookups.
 */
public class TestServiceFactory extends TestCase {
    private static final List lookups = new ArrayList();
    private static final Map bound = new HashMap();

    private String previousFactory;

    public TestServiceFactory(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(TestServiceFactory.class);
    }

    protected void setUp() throws Exception {
        lookups.clear();
        bound.clear();
        previousFactory = System.getProperty(Context.INITIAL_CONTEXT_FACTORY);
        System.setProperty(Context.INITIAL_CONTEXT_FACTORY, RecordingContextFactory.class.getName());
    }

    protected void tearDown() throws Exception {
        if (previousFactory == null) {
            System.getProperties().remove(Context.INITIAL_CONTEXT_FACTORY);
        } else {
            System.setProperty(Context.INITIAL_CONTEXT_FACTORY, previousFactory);
        }
    }

    public void testRefusesUnsupportedMechanismsWithoutLookup() throws Exception {
        String[] names = {
            "client/LdapService", "client/RmiService", "client/JmsService",
            "client/JmxService", "client/JrmpService", "client/JavaService",
            "client/DnsService", "client/IiopService", "client/CorbanameService"
        };
        for (int i = 0; i < names.length; i++) {
            Map env = new HashMap();
            env.put("jndiName", names[i]);
            assertNull(names[i], ServiceFactory.getService(env));
        }
        assertEquals("lookups", 0, lookups.size());
    }

    public void testLooksUpAndBindsOtherNames() throws Exception {
        Map env = new HashMap();
        env.put("jndiName", "client/AxisService");
        Service service = ServiceFactory.getService(env);
        assertNotNull(service);
        assertEquals(1, lookups.size());
        assertEquals("client/AxisService", lookups.get(0));
        assertSame(service, bound.get("client/AxisService"));
        assertSame(service, ServiceFactory.getService(env));
    }

    public void testUsesDefaultNameWhenNoneGiven() throws Exception {
        Service service = ServiceFactory.getService(new HashMap());
        assertNotNull(service);
        assertEquals(1, lookups.size());
        assertEquals("axisServiceName", lookups.get(0));
    }

    public static class RecordingContextFactory implements InitialContextFactory {
        public Context getInitialContext(Hashtable environment) {
            return (Context) Proxy.newProxyInstance(
                    TestServiceFactory.class.getClassLoader(),
                    new Class[] {Context.class},
                    new RecordingContext());
        }
    }

    private static class RecordingContext implements InvocationHandler {
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getDeclaringClass() == Object.class) {
                return method.invoke(this, args);
            }
            String name = method.getName();
            if (name.equals("lookup") && args[0] instanceof String) {
                lookups.add(args[0]);
                Object value = bound.get(args[0]);
                if (value == null) {
                    throw new NameNotFoundException((String) args[0]);
                }
                return value;
            }
            if (name.equals("bind") && args[0] instanceof String) {
                bound.put(args[0], args[1]);
                return null;
            }
            if (name.equals("close")) {
                return null;
            }
            if (name.equals("getEnvironment")) {
                return new Hashtable();
            }
            throw new OperationNotSupportedException(name);
        }
    }
}
