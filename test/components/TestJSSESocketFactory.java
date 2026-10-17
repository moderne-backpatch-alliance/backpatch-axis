/*
 * Copyright 2001-2004 The Apache Software Foundation.
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
package test.components;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.axis.components.net.JSSESocketFactory;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Hashtable;

/**
 * JSSESocketFactory.create must refuse a server whose certificate does not name the host
 * (CVE-2012-5784, CVE-2014-3596). No connection is made: the socket factory, socket and
 * session are in memory and present certificates made with keytool for these tests.
 */
public class TestJSSESocketFactory extends TestCase {

    /** CN=www.example.com, O=Acme; no subjectAltName. */
    private static final String CN_ONLY =
          "-----BEGIN CERTIFICATE-----\n"
        + "MIIBazCCAQ+gAwIBAgIEP3529DAMBggqhkjOPQQDAgUAMCkxDTALBgNVBAoTBEFj\n"
        + "bWUxGDAWBgNVBAMTD3d3dy5leGFtcGxlLmNvbTAgFw0yNjEwMTcxMTM4MDlaGA8y\n"
        + "MTI2MDkyMzExMzgwOVowKTENMAsGA1UEChMEQWNtZTEYMBYGA1UEAxMPd3d3LmV4\n"
        + "YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE87kZGClMTMaT2S8w\n"
        + "ICGnxvjpZc3Fm7dXJhLNHP6wpunAw2yJeCCLIM2NPWA9+6fLMUmnn6mg41bRIESy\n"
        + "556YLKMhMB8wHQYDVR0OBBYEFKVbmzYxPf2b1RBniOzl7J6njgQmMAwGCCqGSM49\n"
        + "BAMCBQADSAAwRQIgWrOp8IQJqLYrVdIScBuX5PON0FN6o5ABFUlcirGLxSoCIQCf\n"
        + "tuk9aozH0puDNdLnE7IV48w/iBvsi0eBiUyutZZFbQ==\n"
        + "-----END CERTIFICATE-----\n";

    /** CN=www.example.com, O=Acme; subjectAltName DNS api.example.com and *.example.net. */
    private static final String SAN =
          "-----BEGIN CERTIFICATE-----\n"
        + "MIIBljCCATygAwIBAgIIQOW0akk4IQYwCgYIKoZIzj0EAwIwKTENMAsGA1UEChME\n"
        + "QWNtZTEYMBYGA1UEAxMPd3d3LmV4YW1wbGUuY29tMCAXDTI2MTAxNzExMzgyMloY\n"
        + "DzIxMjYwOTIzMTEzODIyWjApMQ0wCwYDVQQKEwRBY21lMRgwFgYDVQQDEw93d3cu\n"
        + "ZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS8B4L2oUQa4cOG\n"
        + "dOHUtdzLo10glrBeOZIeXUCGNpAwov+dqjY46XYax7UVZzoRbA4H9RXpwAWRt+b5\n"
        + "9S19pJ4Co0wwSjAdBgNVHQ4EFgQUuU+ZWJgClavB2FEZwzu7zzE83pswKQYDVR0R\n"
        + "BCIwIIIPYXBpLmV4YW1wbGUuY29tgg0qLmV4YW1wbGUubmV0MAoGCCqGSM49BAMC\n"
        + "A0gAMEUCIQCzFntb9Sr/yVC49foOiFQQ19Du+vHWrCeb6hSblB7NUAIgNlwwEW/A\n"
        + "SAH6YQUK+S3aDnby4TEU4n7ZhvtVaxJmro4=\n"
        + "-----END CERTIFICATE-----\n";

    /** CN=attacker.example.org, O="CN=www.example.com". */
    private static final String CN_IN_O =
          "-----BEGIN CERTIFICATE-----\n"
        + "MIIBkTCCATWgAwIBAgIESE9qGjAMBggqhkjOPQQDAgUAMDwxGzAZBgNVBAoTEkNO\n"
        + "PXd3dy5leGFtcGxlLmNvbTEdMBsGA1UEAxMUYXR0YWNrZXIuZXhhbXBsZS5vcmcw\n"
        + "IBcNMjYxMDE3MTEzODEwWhgPMjEyNjA5MjMxMTM4MTBaMDwxGzAZBgNVBAoTEkNO\n"
        + "PXd3dy5leGFtcGxlLmNvbTEdMBsGA1UEAxMUYXR0YWNrZXIuZXhhbXBsZS5vcmcw\n"
        + "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQmqyMupbTnvCfDhTiX7k+rkqw/eFTO\n"
        + "lbSyZAuBSYp+CBNdDTPhLl7ZhyZWiaeIEzHUnJ9Zk8t1pTKCXOIvBD/GoyEwHzAd\n"
        + "BgNVHQ4EFgQUlOpICliJCB/3/OSvb+JaSxgaUFEwDAYIKoZIzj0EAwIFAANIADBF\n"
        + "AiB06w9+6sUNmZ1PfCZbtGP7HOSsXzcgmssNPXxDXcuH4gIhAOlm8pl3L3a2FwpK\n"
        + "6audPc1i+YlWNepqaQmPstxcyERm\n"
        + "-----END CERTIFICATE-----\n";

    public TestJSSESocketFactory(String name) {
        super(name);
    }

    public static Test suite() {
        return new TestSuite(TestJSSESocketFactory.class);
    }

    public void testHostMatchingTheCommonNameIsAccepted() throws Exception {
        assertAccepted(CN_ONLY, "www.example.com");
        assertAccepted(CN_ONLY, "WWW.Example.COM");
    }

    public void testHostNotNamedByTheCertificateIsRefused() throws Exception {
        assertRefused(CN_ONLY, "evil.example.org");
    }

    public void testHostMatchingASubjectAltNameIsAccepted() throws Exception {
        assertAccepted(SAN, "api.example.com");
    }

    public void testWildcardMatchesOneLabelOnly() throws Exception {
        assertAccepted(SAN, "foo.example.net");
        assertRefused(SAN, "a.b.example.net");
        assertRefused(SAN, "example.net");
    }

    public void testCommonNameInsideAnotherAttributeIsNotUsed() throws Exception {
        assertAccepted(CN_IN_O, "attacker.example.org");
        assertRefused(CN_IN_O, "www.example.com");
    }

    private static void assertAccepted(String pem, String host) throws Exception {
        assertNotNull(host, create(pem, host));
    }

    private static void assertRefused(String pem, String host) throws Exception {
        try {
            create(pem, host);
            fail("connection to " + host + " accepted");
        } catch (SSLException expected) {
        }
    }

    private static Socket create(String pem, String host) throws Exception {
        Certificate certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes("US-ASCII")));
        return new InMemoryJSSESocketFactory(new InMemorySSLSocket(certificate))
                .create(host, 443, new StringBuffer(), null);
    }

    private static class InMemoryJSSESocketFactory extends JSSESocketFactory {
        InMemoryJSSESocketFactory(final SSLSocket socket) {
            super(new Hashtable());
            sslFactory = new SSLSocketFactory() {
                public Socket createSocket(String host, int port) {
                    return socket;
                }
                public Socket createSocket(Socket s, String host, int port, boolean autoClose) {
                    return socket;
                }
                public Socket createSocket(String host, int port, InetAddress localHost, int localPort) {
                    return socket;
                }
                public Socket createSocket(InetAddress host, int port) {
                    return socket;
                }
                public Socket createSocket(InetAddress host, int port, InetAddress localHost, int localPort) {
                    return socket;
                }
                public String[] getDefaultCipherSuites() {
                    return new String[0];
                }
                public String[] getSupportedCipherSuites() {
                    return new String[0];
                }
            };
        }
    }

    private static class InMemorySSLSocket extends SSLSocket {
        private final SSLSession session;

        InMemorySSLSocket(final Certificate certificate) {
            session = (SSLSession) Proxy.newProxyInstance(SSLSession.class.getClassLoader(),
                    new Class[] {SSLSession.class}, new InvocationHandler() {
                        public Object invoke(Object proxy, Method method, Object[] args) {
                            if ("getPeerCertificates".equals(method.getName())) {
                                return new Certificate[] {certificate};
                            }
                            throw new UnsupportedOperationException(method.getName());
                        }
                    });
        }

        public SSLSession getSession() {
            return session;
        }

        public void startHandshake() {
        }

        public String[] getSupportedCipherSuites() {
            return new String[0];
        }

        public String[] getEnabledCipherSuites() {
            return new String[0];
        }

        public void setEnabledCipherSuites(String[] suites) {
        }

        public String[] getSupportedProtocols() {
            return new String[0];
        }

        public String[] getEnabledProtocols() {
            return new String[0];
        }

        public void setEnabledProtocols(String[] protocols) {
        }

        public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        }

        public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        }

        public void setUseClientMode(boolean mode) {
        }

        public boolean getUseClientMode() {
            return true;
        }

        public void setNeedClientAuth(boolean need) {
        }

        public boolean getNeedClientAuth() {
            return false;
        }

        public void setWantClientAuth(boolean want) {
        }

        public boolean getWantClientAuth() {
            return false;
        }

        public void setEnableSessionCreation(boolean flag) {
        }

        public boolean getEnableSessionCreation() {
            return true;
        }
    }
}
