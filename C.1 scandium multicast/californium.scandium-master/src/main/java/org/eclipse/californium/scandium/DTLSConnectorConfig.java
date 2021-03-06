/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Julien Vermillard - Sierra Wireless
 *******************************************************************************/

package org.eclipse.californium.scandium;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

/**
 * A class centralizing configuration options for the DTLS connector.
 */
public class DTLSConnectorConfig {

    /** the maximum fragment size before DTLS fragmentation must be applied */
    private int maxFragmentLength = 4096;
    
    /** The overhead for the record header (13 bytes) and the handshake header (12 bytes) is 25 bytes */
    private int maxPayloadSize = maxFragmentLength + 25;

    /** The initial timer value for retransmission; rfc6347, section: 4.2.4.1 */
    private int retransmissionTimeout = 1000;
    
    /** Maximal number of retransmissions before the attempt to transmit a message is canceled */
    private int maxRetransmit = 4;
    
    /** do the server require the client to authenticate */
    public boolean requireClientAuth = true;
    
    /** do we send only the raw key (RPK) and not the full certificate (X509)*/
    public boolean sendRawKey=true;
    
    /** store of the PSK */
    public PskStore pskStore = null;
    
    /** the private key for RPK and X509 mode */
    public PrivateKey privateKey = null;
    
    /** the certificate for RPK and X509 mode */
    public Certificate[] certChain = null;
        
    /** the favorite cipher suite */
    public CipherSuite preferredCipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
    
    private DTLSConnector connector;
     
    public DTLSConnectorConfig(DTLSConnector connector) {
        this.connector = connector;
    }
    

	private void checkStarted() {
       if (connector.isRunning()) {
	        throw new IllegalStateException("can't configure the DTLS connector, it's already started");
       }
    }
    
    /**
     * Set the Pre-shared key store for PSK mode. 
     * @param pskStore the key store for PSK mode
	 */
    public void setPskStore(PskStore pskStore) {
	    checkStarted();
        this.pskStore = pskStore;   
	}
	
	/**
     * Set the key for raw private key or full X509 mode.
     * @param key the private key
     * @param certChain the chain of certificate
     * @param sendRawKey <code>true</code> we need to send raw public cert, <code>false</code> for X509
     */
     public void setPrivateKey(PrivateKey key, Certificate[] certChain, boolean sendRawKey) {
	    checkStarted();
        this.privateKey = key;
        this.certChain = certChain;
        this.sendRawKey = sendRawKey;
	}
	
	/**
	 * Does the server require clients to authenticate.
	 * @param requireClientAuth set to <code>true</code> if you require the 
	 * clients to authenticate 
	 */
    public void setRequireClientAuth(boolean requireClientAuth) {
	    checkStarted();
        this.requireClientAuth = requireClientAuth;
	}
	
	/**
     * Set the favorite cipher suite which is going to be placed a the 
	 * top of the advertised supported cipher suites.
	 * @param suite
	 */
    public void setPreferredCipherSuite(CipherSuite suite) {
	    checkStarted();
        this.preferredCipherSuite = suite;
	}
	
    // SETTER/GETTER
    
    public int getMaxFragmentLength() {
        return maxFragmentLength;
    }

    public void setMaxFragmentLength(int maxFragmentLength) {
        this.maxFragmentLength = maxFragmentLength;
    }

    public int getMaxPayloadSize() {
        return maxPayloadSize;
    }

    public void setMaxPayloadSize(int maxPayloadSize) {
        this.maxPayloadSize = maxPayloadSize;
    }

    public int getRetransmissionTimeout() {
        return retransmissionTimeout;
    }

    public void setRetransmissionTimeout(int retransmissionTimeout) {
        this.retransmissionTimeout = retransmissionTimeout;
    }

    public int getMaxRetransmit() {
        return maxRetransmit;
    }

    public void setMaxRetransmit(int maxRetransmit) {
        this.maxRetransmit = maxRetransmit;
    }
}
