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
package test.encoding;

import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.Version;
import org.apache.axis.constants.Style;
import test.GenericLocalTest;

/**
 * The Version service answers in whatever namespace URI the request used, so an unescaped
 * namespace declaration in the response lets the caller inject markup. Request taken from
 * upstream's axis-war XssTest (getVersion-xss.xml), sent to an in-process AxisServer.
 */
public class TestXss extends GenericLocalTest {
    private static final String REQUEST =
        "<soapenv:Envelope\n" +
        "    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
        "    xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n" +
        "    xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\n" +
        "    xmlns:axis=\"http://axis.apache.org&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x22;&#x3e;&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x20;&#x78;&#x6d;&#x6c;&#x6e;&#x73;&#x3d;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3a;&#x2f;&#x2f;&#x77;&#x77;&#x77;&#x2e;&#x77;&#x33;&#x2e;&#x6f;&#x72;&#x67;&#x2f;&#x31;&#x39;&#x39;&#x39;&#x2f;&#x78;&#x68;&#x74;&#x6d;&#x6c;&#x22;&#x3e;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;&#x48;&#x65;&#x6c;&#x6c;&#x6f;&#x27;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;\">\n" +
        "  <soapenv:Body>\n" +
        "    <axis:getVersion soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"/>\n" +
        "  </soapenv:Body>\n" +
        "</soapenv:Envelope>\n";

    public TestXss(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        super.setUp(false);
        deploy("Version", Version.class, Style.RPC);
    }

    public void testGetVersion() throws Exception {
        MessageContext msgContext = new MessageContext(server);
        msgContext.setRequestMessage(new Message(REQUEST));
        msgContext.setTargetService("Version");
        server.invoke(msgContext);
        String response = msgContext.getResponseMessage().getSOAPPartAsString();
        assertTrue(response, response.indexOf("getVersionResponse") != -1);
        assertTrue(response, response.indexOf("<script") == -1);
    }
}
