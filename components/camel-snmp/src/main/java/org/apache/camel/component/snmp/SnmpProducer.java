/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.component.snmp;

import org.apache.camel.Exchange;
import org.apache.camel.support.DefaultProducer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.AbstractTarget;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.AbstractVariable;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.TimeoutException;

/**
 * A snmp producer
 */
public class SnmpProducer extends DefaultProducer {

    private static final Logger LOG = LoggerFactory.getLogger(SnmpProducer.class);

    private SnmpEndpoint endpoint;

    private Address targetAddress;
    private USM usm;
    private AbstractTarget target;
    private SnmpActionType actionType;
    private PDU pdu;

    public SnmpProducer(SnmpEndpoint endpoint, SnmpActionType actionType) {
        super(endpoint);
        this.endpoint = endpoint;
        this.actionType = actionType;
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        this.targetAddress = GenericAddress.parse(this.endpoint.getAddress());
        LOG.debug("targetAddress: {}", targetAddress);

        switch (this.endpoint.getSnmpVersion()) {
            // The value 0 means SNMPv1,
            case 0: {

            }
            // 1 means SNMPv2c,
            case 1: {
                CommunityTarget requestTarget = new CommunityTarget();
                requestTarget.setCommunity(new OctetString(endpoint.getSnmpCommunity()));
                this.target = requestTarget;

                this.pdu = new PDU();
                break;
            }
            // and the value 3 means SNMPv3.
            case 3: {
                SecurityProtocols protocols = SecurityProtocols.getInstance();
                protocols.addDefaultProtocols();
                this.usm = new USM(protocols, new OctetString(MPv3.createLocalEngineID()), 0);

                UserTarget userTarget = new UserTarget();

                OID authenticationProtocol = null;
                OID privacyProtocol = null;
                switch (this.endpoint.getSecurityLevel()) {
                    case 1: {
                        userTarget.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);
                        break;
                    }
                    case 2: {
                        if (this.endpoint.getAuthenticationProtocol().equalsIgnoreCase("MD5"))
                            authenticationProtocol = AuthMD5.ID;
                        else if (this.endpoint.getAuthenticationProtocol().equalsIgnoreCase("SHA1"))
                            authenticationProtocol = AuthSHA.ID;
                        userTarget.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
                        break;
                    }
                    case 3: {
                        if (this.endpoint.getAuthenticationProtocol().equalsIgnoreCase("MD5"))
                            authenticationProtocol = AuthMD5.ID;
                        else if (this.endpoint.getAuthenticationProtocol().equalsIgnoreCase("SHA1"))
                            authenticationProtocol = AuthSHA.ID;

                        if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("DES"))
                            privacyProtocol = PrivDES.ID;
                        else if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("TRIDES"))
                            privacyProtocol = Priv3DES.ID;
                        else if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("AES128"))
                            privacyProtocol = PrivAES128.ID;
                        else if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("AES192"))
                            privacyProtocol = PrivAES192.ID;
                        else if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("AES256"))
                            privacyProtocol = PrivAES256.ID;

                        userTarget.setSecurityLevel(SecurityLevel.AUTH_PRIV);
                        break;
                    }
                }

                OctetString userName = new OctetString(this.endpoint.getSecurityName());
                OctetString userAuthPassword = new OctetString(this.endpoint.getAuthenticationPassphrase());
                OctetString privacyPassphrase = new OctetString(this.endpoint.getPrivacyPassphrase());
                UsmUser usmUser = new UsmUser(userName, authenticationProtocol, userAuthPassword, privacyProtocol, privacyPassphrase);

                this.usm.addUser(usmUser);
                SecurityModels.getInstance().addSecurityModel(this.usm);

                userTarget.setSecurityName(userName);
                this.target = userTarget;

                this.pdu = new ScopedPDU();
                break;
            }
        }

        this.target.setAddress(this.targetAddress);
        this.target.setRetries(this.endpoint.getRetries());
        this.target.setTimeout(this.endpoint.getTimeout());
        this.target.setVersion(this.endpoint.getSnmpVersion());

        // in here,only POLL do set the oids
        if (this.actionType == SnmpActionType.POLL) {
            for (OID oid : this.endpoint.getOids()) {
                this.pdu.add(new VariableBinding(oid));
            }
        }
        this.pdu.setErrorIndex(0);
        this.pdu.setErrorStatus(0);
        this.pdu.setMaxRepetitions(0);
        // support POLL and GET_NEXT
        if (this.actionType == SnmpActionType.GET_NEXT) {
            this.pdu.setType(PDU.GETNEXT);
        } else {
            this.pdu.setType(PDU.GET);
        }
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        try {
            SecurityModels.getInstance().removeSecurityModel(new Integer32(this.usm.getID()));
        } finally {
            this.targetAddress = null;
            this.usm = null;
            this.target = null;
            this.pdu = null;
        }
    }

    @Override
    public void process(final Exchange exchange) throws Exception {
        // load connection data only if the endpoint is enabled
        Snmp snmp = null;
        TransportMapping<? extends Address> transport = null;

        try {
            LOG.debug("Starting SNMP producer on {}", this.endpoint.getAddress());

            // either tcp or udp
            if ("tcp".equals(this.endpoint.getProtocol())) {
                transport = new DefaultTcpTransportMapping();
            } else if ("udp".equals(this.endpoint.getProtocol())) {
                transport = new DefaultUdpTransportMapping();
            } else {
                throw new IllegalArgumentException("Unknown protocol: " + this.endpoint.getProtocol());
            }

            snmp = new Snmp(transport);

            LOG.debug("Snmp: i am sending");

            snmp.listen();

            if (this.actionType == SnmpActionType.GET_NEXT) {
                // snmp walk
                List<SnmpMessage> smLst = new ArrayList<>();
                for (OID oid : this.endpoint.getOids()) {
                    this.pdu.clear();
                    this.pdu.add(new VariableBinding(oid));

                    boolean matched = true;
                    while (matched) {
                        ResponseEvent responseEvent = snmp.send(this.pdu, this.target);
                        if (responseEvent == null || responseEvent.getResponse() == null) {
                            break;
                        }
                        PDU response = responseEvent.getResponse();
                        String nextOid = null;
                        Vector<? extends VariableBinding> variableBindings = response.getVariableBindings();
                        for (int i = 0; i < variableBindings.size(); i++) {
                            VariableBinding variableBinding = variableBindings.elementAt(i);
                            nextOid = variableBinding.getOid().toDottedString();
                            if (!nextOid.startsWith(oid.toDottedString())) {
                                matched = false;
                                break;
                            }
                        }
                        if (!matched) {
                            break;
                        }
                        this.pdu.clear();
                        pdu.add(new VariableBinding(new OID(nextOid)));
                        smLst.add(new SnmpMessage(getEndpoint().getCamelContext(), response));
                    }
                }
                exchange.getIn().setBody(smLst);
            } else {
                if (endpoint.getOperation() != null && endpoint.getOperation().equals("set")) {
                    OID oidToSet = new OID(exchange.getIn().getHeader("oid", String.class));
                    String valueToSet = exchange.getIn().getHeader("value", String.class);
                    Class<? extends AbstractVariable> valueType = exchange.getIn().getHeader("valueType", Class.class);
                    AbstractVariable value = createVariable(valueType, valueToSet);

                    pdu.clear();
                    pdu.setType(PDU.SET);
                    pdu.add(new VariableBinding(oidToSet, value));

                    ResponseEvent response = snmp.send(pdu, target);
                    LOG.debug("Snmp: snmp-set sent");
                    handleResponse(response, exchange);
                } else {
                    ResponseEvent responseEvent = snmp.send(pdu, target);
                    LOG.debug("Snmp: snmp-get sent");
                    handleResponse(responseEvent, exchange);
                }
            }
        } finally {
            try {
                transport.close();
            } catch (Exception e) {
                LOG.error("Error closing transport", e);
            }
            try {
                snmp.close();
            } catch (Exception e) {
                LOG.error("Error closing SNMP", e);
            }
        }
    } //end process

    // Handles the response from the SNMP agent and sets the body of the exchange
    private void handleResponse(ResponseEvent response, Exchange exchange) throws TimeoutException {
        if (response != null && response.getResponse() != null) {
            exchange.getIn().setBody(new SnmpMessage(getEndpoint().getCamelContext(), response.getResponse()));
        } else {
            throw new TimeoutException("SNMP Producer Timeout" + (response != null ? " on SET" : ""));
        }
    }

    // Creates an AbstractVariable based on the value type and value to set
    private AbstractVariable createVariable(Class<? extends AbstractVariable> valueType, String valueToSet) {
        switch (valueType.getSimpleName()) {
            case "Integer32":
                return new Integer32(Integer.parseInt(valueToSet));
            case "OctetString":
                return new OctetString(new String(valueToSet));
            default:
                throw new IllegalArgumentException("Unknown value type: " + valueType.getSimpleName());
        }
    }
}
