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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.TimeoutException;

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
import org.snmp4j.security.SecurityModel;
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

/**
 * A snmp producer
 */
public class SnmpProducer extends DefaultProducer {

    private static final Logger LOG = LoggerFactory.getLogger(SnmpProducer.class);

    private SnmpEndpoint endpoint;

    private Address targetAddress;
    //private USM usm;
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
                CommunityTarget requestTarget = new CommunityTarget();
                requestTarget.setCommunity(new OctetString(endpoint.getSnmpCommunity()));
                this.target = requestTarget;

                this.pdu = new PDU();
                break;
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
                USM usm = (USM) SecurityModels.getInstance().getSecurityModel(new Integer32(SecurityModel.SECURITY_MODEL_USM));
                if (usm == null) {
                    usm = new USM(protocols, new OctetString(MPv3.createLocalEngineID()), 0);
                }
                UserTarget userTarget = new UserTarget();

                OID authenticationProtocol = null;
                OID privacyProtocol = null;
                switch (this.endpoint.getSecurityLevel()) {
                    case 1: {
                        userTarget.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);
                        break;
                    }
                    case 2: {
                        if (this.endpoint.getAuthenticationProtocol().equalsIgnoreCase("MD5")) {
                            authenticationProtocol = AuthMD5.ID;
                        } else if (this.endpoint.getAuthenticationProtocol().equalsIgnoreCase("SHA1")) {
                            authenticationProtocol = AuthSHA.ID;
                        }
                        userTarget.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
                        break;
                    }
                    case 3: {
                        if (this.endpoint.getAuthenticationProtocol().equalsIgnoreCase("MD5")) {
                            authenticationProtocol = AuthMD5.ID;
                        } else if (this.endpoint.getAuthenticationProtocol().equalsIgnoreCase("SHA1")) {
                            authenticationProtocol = AuthSHA.ID;
                        }

                        if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("DES")) {
                            privacyProtocol = PrivDES.ID;
                        } else if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("TRIDES")) {
                            privacyProtocol = Priv3DES.ID;
                        }  else if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("AES128")) {
                            privacyProtocol = PrivAES128.ID;
                        } else if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("AES192")) {
                            privacyProtocol = PrivAES192.ID;
                        } else if (this.endpoint.getPrivacyProtocol().equalsIgnoreCase("AES256")) {
                            privacyProtocol = PrivAES256.ID;
                        }
                        userTarget.setSecurityLevel(SecurityLevel.AUTH_PRIV);
                        break;
                    }
                    default: {
                        // NOP
                    }
                }

                OctetString userName = new OctetString(this.endpoint.getSecurityName());
                OctetString userAuthPassword = new OctetString(this.endpoint.getAuthenticationPassphrase());
                OctetString privacyPassphrase = new OctetString(this.endpoint.getPrivacyPassphrase());
                UsmUser usmUser = new UsmUser(userName, authenticationProtocol, userAuthPassword, privacyProtocol, privacyPassphrase);
                usm.addUser(usmUser);

                SecurityModel sm = SecurityModels.getInstance().getSecurityModel(new Integer32(SecurityModel.SECURITY_MODEL_USM));
                if ( sm == null ) {
                    SecurityModels.getInstance().addSecurityModel(usm);
                }

                userTarget.setSecurityName(userName);
                this.target = userTarget;

                this.pdu = new ScopedPDU();
                break;
            }
            default: {
                // NOP
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
            SecurityModels.getInstance().removeSecurityModel(new Integer32(SecurityModel.SECURITY_MODEL_ANY));
            SecurityModels.getInstance().removeSecurityModel(new Integer32(SecurityModel.SECURITY_MODEL_SNMPv1));
            SecurityModels.getInstance().removeSecurityModel(new Integer32(SecurityModel.SECURITY_MODEL_SNMPv2c));
            SecurityModels.getInstance().removeSecurityModel(new Integer32(SecurityModel.SECURITY_MODEL_USM));
            SecurityModels.getInstance().removeSecurityModel(new Integer32(SecurityModel.SECURITY_MODEL_TSM));
        } finally {
            this.targetAddress = null;
            //this.usm = null;
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

            LOG.debug("Snmp: i am sending {}", this.target.getAddress());

            snmp.listen();

            if (this.actionType == SnmpActionType.GET_NEXT) {
                performSnmpWalk( exchange, snmp );
            } else {
                if (this.endpoint.getOperation() != null && this.endpoint.getOperation().equals("set")) {
                    performSnmpSet( exchange, snmp );
                } else {
                    performSnmpGet( exchange, snmp );
                }
            }
        } catch ( TimeoutException te ) {
            LOG.error( "Request Timeout, no response: {} {}", this.target.getAddress(), te.getMessage() );
        } catch ( Exception e ) {
            //LOG.error( "Error", e );
            throw e;
        } finally {
            closeResources( transport, snmp );
        }
    } //end process

    private void closeResources ( TransportMapping < ? extends Address > transport, Snmp snmp ) {
        try {
            if ( transport != null ) {
                LOG.debug( "Closing transport {} {}", transport, this.target.getAddress() );
                transport.close();
            }
        } catch (Exception e) {
            LOG.error("Error closing transport", e);
        }
        try {
            if ( snmp != null ) {
                LOG.debug( "Closing snmp {} {}", snmp, this.target.getAddress() );
                snmp.close();
            }
        } catch (Exception e) {
            LOG.error("Error closing SNMP", e);
        }
    }

    private void performSnmpGet ( Exchange exchange, Snmp snmp ) throws IOException, TimeoutException {
        ResponseEvent responseEvent = snmp.send(pdu, target);
        LOG.debug("Snmp: snmp-get sent {}", this.target.getAddress());
        handleResponse(responseEvent, exchange );
    }

    private void performSnmpSet ( Exchange exchange, Snmp snmp ) throws ClassNotFoundException, IOException, TimeoutException {
        String value = this.endpoint.getValue();
        String valueTypeClassName = this.endpoint.getValueType();
        Class <? extends AbstractVariable> valueTypeClazz = Class.forName( valueTypeClassName ).asSubclass( AbstractVariable.class );
        OIDList oidList = this.endpoint.getOids();
        AbstractVariable abstractVariable = createVariable(valueTypeClazz, value);

        pdu.clear();
        pdu.setType(PDU.SET);
        for (OID oid : oidList) {
            VariableBinding vb = new VariableBinding(oid, abstractVariable);
            pdu.add(vb);
        }
        ResponseEvent response = snmp.send(pdu, target);
        LOG.debug("Snmp: snmp-set sent {}", this.target.getAddress());
        handleResponse(response, exchange );
    }

    // Handles the response from the SNMP agent and sets the body of the exchange
    private void handleResponse(ResponseEvent response, Exchange exchange) throws TimeoutException {
        if (response != null && response.getResponse() != null) {
            exchange.getIn().setBody(new SnmpMessage(getEndpoint().getCamelContext(), response.getResponse()));
        } else {
            throw new TimeoutException("SNMP Producer Timeout" + (response != null ? " on " + this.endpoint.getOperation() : ""));
        }
    }

    private void performSnmpWalk ( Exchange exchange, Snmp snmp ) throws IOException {
        // snmp walk
        List<SnmpMessage> smLst = new ArrayList<>();
        for (OID oid : this.endpoint.getOids()) {
            this.pdu.clear();
            this.pdu.add(new VariableBinding(oid));

            boolean matched = true;
            while (matched) {
                ResponseEvent responseEvent = snmp.send(this.pdu, this.target);
                LOG.debug("Snmp: snmp-get-next sent {}", this.target.getAddress());
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
    }

    // Creates an AbstractVariable based on the value type and value to set
    private AbstractVariable createVariable(Class<? extends AbstractVariable> valueType, String valueToSet) {
        if (valueType.equals(Integer32.class)) {
            return new Integer32(Integer.parseInt(valueToSet));
        } else if (valueType.equals(OctetString.class)) {
            return new OctetString(valueToSet);
        } else if (valueType.equals(OID.class)) {
            return new OID(valueToSet);
        }
        throw new IllegalArgumentException("Unsupported SNMP type: "+valueType.getName());
    }
}
