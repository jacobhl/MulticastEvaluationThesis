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
 ******************************************************************************/


package org.eclipse.californium.scandium.examples;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import javax.xml.bind.DatatypeConverter;















import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.MulticastDTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;




public class ExampleDTLSMulticastServer {

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.ALL);
	}

	private static final int DEFAULT_PORT = 5684; 
	private static final int MULTICAST_PORT = 11000;
	
	private static final InetSocketAddress MULTICAST_ADDR = new InetSocketAddress("224.224.224.224" ,11000); //"FF7E:230::1234"
	
	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private final static String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
    private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

    private List<RawData> multicastGroup = new ArrayList<RawData>();
	private DTLSConnector dtlsConnector;
	private static MulticastDTLSConnector dtlsConnectorMulticast;
	
	private byte[] aesKey = new byte[]{(byte) 0xC9, 0x0E, 0x6A, (byte) 0xA2, (byte) 0xEF, 0x60, 0x34, (byte) 0x96,
			(byte) 0x90, 0x54, (byte) 0xC4, (byte) 0x96, 0x65, (byte) 0xBA, 0x03, (byte) 0x9E};
	private byte[] client_iv = new byte[]{0x55, 0x23, 0x2F, (byte) 0xA3};
	
	public ExampleDTLSMulticastServer() {
	    InMemoryPskStore pskStore = new InMemoryPskStore();
        // put in the PSK store the default identity/psk for tinydtls tests
        pskStore.setKey("Client_identity", "secretPSK".getBytes());
	   
	    try {
	        // load the key store
	        KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream in = new FileInputStream(KEY_STORE_LOCATION);
            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());

            // load the trust store
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
            
            // You can load multiple certificates if needed
            Certificate[] trustedCertificates = new Certificate[1];
            trustedCertificates[0] = trustStore.getCertificate("root");
            
            dtlsConnector = new DTLSConnector(new InetSocketAddress(DEFAULT_PORT),trustedCertificates);
            dtlsConnector.SetKey(aesKey, client_iv);
            dtlsConnector.getConfig().setPrivateKey((PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("server"),true);
            dtlsConnector.getConfig().setPskStore(pskStore);
            
            dtlsConnector.setRawDataReceiver(new RawDataChannelImpl(dtlsConnector));

        } catch (GeneralSecurityException | IOException e) {
            System.err.println("Could not load the keystore");
            e.printStackTrace();
        }
	    multicastServer();
	}
	
	public void multicastServer(){
		InMemoryPskStore pskStore = new InMemoryPskStore();
        // put in the PSK store the default identity/psk for tinydtls tests
        pskStore.setKey("Client_identity", "secretPSK".getBytes());
	   
	    try {
	        // load the key store
	        KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream in = new FileInputStream(KEY_STORE_LOCATION);
            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());

            // load the trust store
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
            
            // You can load multiple certificates if needed
            Certificate[] trustedCertificates = new Certificate[1];
            trustedCertificates[0] = trustStore.getCertificate("root");
            
            InetSocketAddress addr = new InetSocketAddress(MULTICAST_ADDR.getAddress() ,MULTICAST_ADDR.getPort());
            dtlsConnectorMulticast = new MulticastDTLSConnector(addr, trustedCertificates);
            dtlsConnectorMulticast.SetKey(aesKey, client_iv);
            dtlsConnectorMulticast.SetMulticastID(199);
            dtlsConnectorMulticast.getConfig().setPrivateKey((PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("server"),true);
            dtlsConnectorMulticast.getConfig().setPskStore(pskStore);
            
            dtlsConnectorMulticast.setRawDataReceiver(new RawDataChannelImpl(dtlsConnector));

        } catch (GeneralSecurityException | IOException e) {
            System.err.println("Could not load the keystore");
            e.printStackTrace();
        }
		
	}
	
	
	
	public void start() {
		try {
			dtlsConnector.start();
			dtlsConnectorMulticast.start();
		} catch (IOException e) {
			throw new IllegalStateException("Unexpected error starting the DTLS UDP server",e);
		}
	}
	
	private class RawDataChannelImpl implements RawDataChannel {
		
		private Connector connector;
		
		public RawDataChannelImpl(Connector con) {
			this.connector = con;
		}

		// @Override
		public void receiveData(final RawData raw) {
			if (raw.getAddress() == null)
				throw new NullPointerException();
			if (raw.getPort() == 0)
				throw new NullPointerException();
			
			System.out.println(new String(raw.getBytes()));
			connector.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
			
			try {
				if(new String(raw.getBytes(), "UTF-8").equals("REQJOINMULTI"))
				{
					multicastGroup.add(raw);
					Thread.sleep(1000);
					
					UpdateGSA(connector);
					
					
					Thread.sleep(5000);
					
					RawData Message2 = new RawData("You have joined the group".getBytes(), raw.getAddress(), raw.getPort());
					//multicastMessage.setMulticast(true);
					//connector.send(Message2);	
					
					
					//connector.send(new RawData("GSA: ".getBytes(), raw.getAddress(), raw.getPort()));				
				}
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	public static void sendMulticast() throws InterruptedException
	{
		RawData multicastMessage = new RawData("Everyone in the group gets this message.".getBytes(), MULTICAST_ADDR.getAddress() ,MULTICAST_ADDR.getPort()+1);
		multicastMessage.setMulticast(true);
		//connector.send(multicastMessage);
		for (int k = 0; k<60;k++)
		{
			dtlsConnectorMulticast.send(multicastMessage);
			Thread.sleep(50);
		}
		Thread.sleep(5000);
	}
	
	public void UpdateGSA(Connector conn) throws UnsupportedEncodingException
	{
		//int i = 0;
		String listID = "";
		for (int j = 0; j< multicastGroup.size(); j++)
		{
			if(multicastGroup.get(j) != null)
			{
				listID += Integer.toString(j) + "-";
			}
		}
		listID = listID.substring(0, listID.length()-1);
		
		for(int i = 0; i < multicastGroup.size(); i++)
		{
			if(multicastGroup.get(i) != null)
			{
				String GSA = "GSA|" + Integer.toString(i) + ";";
				GSA += "multicastadd|" + "224.224.224.224:11001;";
				GSA += "TPK|" + DatatypeConverter.printHexBinary(aesKey) + ";";
				GSA += "IV|" + DatatypeConverter.printHexBinary(client_iv) + ";";
				GSA += "listID|" + listID + ";";
				RawData Message = new RawData(GSA.getBytes(), multicastGroup.get(i).getAddress(), multicastGroup.get(i).getPort());
				conn.send(Message);
			}
		}
		//connector.send(new RawData("GSA: ".getBytes(), raw.getAddress(), raw.getPort()));	
		//RawData Message = new RawData("GSA".getBytes(), raw.getAddress(), raw.getPort());
		//multicastMessage.setMulticast(true);
		//connector.send(Message);	
	}
	
	public static void main(String[] args) {
		//System.setProperty("java.net.preferIPv4Stack" , "true");
		System.setProperty("java.net.preferIPv6Stack" , "true");
		ExampleDTLSMulticastServer server = new ExampleDTLSMulticastServer();
		server.start();
		
		try {
			System.in.read();
			sendMulticast();
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
	}
}
