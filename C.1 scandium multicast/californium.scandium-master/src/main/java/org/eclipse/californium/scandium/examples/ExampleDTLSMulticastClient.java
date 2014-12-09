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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Level;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.MulticastDTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;


public class ExampleDTLSMulticastClient {

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINE);
	}

	private static final int DEFAULT_PORT = 5684;
	private static final InetSocketAddress MULTICAST_ADDR = new InetSocketAddress("224.224.224.224" ,11001);
	
	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private final static String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

	private DTLSConnector dtlsConnector;
	private MulticastDTLSConnector dtlsConnectorMulticast;
	private static InetSocketAddress unicastAddress; 
	private static InetSocketAddress serverAddress;
	
	private static String clientID = "";
	
	
	
	public ExampleDTLSMulticastClient() {
	    try {
	        // load key store
            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream in = new FileInputStream(KEY_STORE_LOCATION);
            keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
    
            // load trust store
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
            trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
            
            // You can load multiple certificates if needed
            Certificate[] trustedCertificates = new Certificate[1];
            trustedCertificates[0] = trustStore.getCertificate("root");
    
    		dtlsConnector = new DTLSConnector(new InetSocketAddress(0), trustedCertificates);
    		dtlsConnector.getConfig().setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
    		dtlsConnector.getConfig().setPrivateKey((PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("client"), true);
    		
    		dtlsConnector.setRawDataReceiver(new RawDataChannelImpl());
    		
	    } catch (GeneralSecurityException | IOException e) {
            System.err.println("Could not load the keystore");
            e.printStackTrace();
        }
	}
	
	public void listenMulticast(byte[] AESkey, byte[] IV) 
	{
        // load key store
        KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("JKS");

        InputStream in = new FileInputStream(KEY_STORE_LOCATION);
        keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());

        // load trust store
        KeyStore trustStore = KeyStore.getInstance("JKS");
        InputStream inTrust = new FileInputStream(TRUST_STORE_LOCATION);
        trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());
        
        // You can load multiple certificates if needed
        Certificate[] trustedCertificates = new Certificate[1];
        trustedCertificates[0] = trustStore.getCertificate("root");
		
        InetSocketAddress addr = new InetSocketAddress(MULTICAST_ADDR.getAddress() ,MULTICAST_ADDR.getPort());
        
		dtlsConnectorMulticast = new MulticastDTLSConnector(addr, trustedCertificates);
		dtlsConnectorMulticast.SetKey(AESkey, IV);
		dtlsConnectorMulticast.getConfig().setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
		dtlsConnectorMulticast.getConfig().setPrivateKey((PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray()), keyStore.getCertificateChain("client"), true);
		
		dtlsConnectorMulticast.setRawDataReceiver(new RawDataChannelImpl());
		dtlsConnectorMulticast.start();
		}
		catch (KeyStoreException | FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void test() {
		try {
			dtlsConnector.start();
			
			//InetSocketAddress servAdd = new InetSocketAddress("10.192.41.99" ,0); //jacob			
			//InetSocketAddress servAdd = new InetSocketAddress("10.192.99.206" ,0);  //kasper
			//InetSocketAddress servAdd = new InetSocketAddress("10.192.51.204" ,0);  //ubuntu eduroam
			
			//InetSocketAddress servAdd = new InetSocketAddress("192.168.1.2" ,0); //jacob 3COM
			//InetSocketAddress servAdd = new InetSocketAddress("192.168.1.7" ,0); //Kasper 3COM
			
			//InetSocketAddress servAdd = new InetSocketAddress("192.168.1.5" ,0);  //ubuntu 3com
			
			
			//InetSocketAddress servAdd = new InetSocketAddress("192.168.236.1" ,0);  //ubuntu localmac
			
			InetSocketAddress servAdd = new InetSocketAddress("192.168.1.137" ,0); //jacob N600
			//InetSocketAddress servAdd = new InetSocketAddress("192.168.1.134" ,0);  //ubuntu N600
			
			//InetSocketAddress servAdd = new InetSocketAddress("::1" ,0); //localhost ipv6
			
			
			//dtlsConnector.send(new RawData("REQJOINMULTI".getBytes(), servAdd.getAddress() , DEFAULT_PORT));
			dtlsConnector.send(new RawData("REQJOINMULTI".getBytes(), InetAddress.getByName("localhost") , DEFAULT_PORT));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private class RawDataChannelImpl implements RawDataChannel {

		// @Override
		public void receiveData(final RawData raw) {
			
			System.out.println(raw.getAddress() + ":" + raw.getPort() + ": ClientID: " + clientID + ": received message: " + new String(raw.getBytes()));
			try {
				String received = new String(raw.getBytes(), "UTF-8");
				if(received.startsWith("GSA"))
				{
					//serverAddress.
					// LISTEN ON MULTICAST
					byte[] aesKey = null; // = new byte[]{(byte) 0xC9, 0x0E, 0x6A, (byte) 0xA2, (byte) 0xEF, 0x60, 0x34, (byte) 0x96, (byte) 0x90, 0x54, (byte) 0xC4, (byte) 0x96, 0x65, (byte) 0xBA, 0x03, (byte) 0x9E};
					byte[] client_iv = null; //new byte[]{0x55, 0x23, 0x2F, (byte) 0xA3};
					
					String[] receivedArr = received.split(";");
					String temp = "";
					for (String item : receivedArr) {
						switch (item.substring(0, item.indexOf("|"))) {
						case "GSA":
							//own GSA ID
							break;

						case "multicastadd":
							//The multicastaddress we need to connect to
							break;
						case "TPK":
							aesKey = DatatypeConverter.parseHexBinary(item.substring(item.indexOf("|")+1, item.length())); 
							break;
						case "IV":
							client_iv = DatatypeConverter.parseHexBinary(item.substring(item.indexOf("|")+1, item.length())); 
							break;
						case "listID":
							// List of other ID's in the group
							break;
						default:
							System.out.println("Unknown content type: " + item);
							break;
						}
						temp = item.substring(item.indexOf("|")+1, item.length());
					    System.out.println(temp);
					}
					//byte[] b = receivedArr[2].substring(4, receivedArr[2].length()-5).getBytes();
					
		            listenMulticast(aesKey, client_iv);					
				}
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//dtlsConnector.close(new InetSocketAddress("localhost" , DEFAULT_PORT));
			
			// notify main thread to exit
			//synchronized (ExampleDTLSMulticastClient.class) {
			//	ExampleDTLSMulticastClient.class.notify();
			//}
		}
	}
	
	public static void main(String[] args) throws InterruptedException {
		
		if (args.length > 0) {
		    try {
		    	//serverAddress = new InetSocketAddress(args[0], DEFAULT_PORT);
		    	//System.out.println(serverAddress.getHostName());
		    	clientID = args[0];
		    } catch (NumberFormatException e) {
		        System.err.println("Argument" + args[0] + " must be an integer.");
		        System.exit(1);
		    }
		}
		else
		{
		}
		
		ExampleDTLSMulticastClient client = new ExampleDTLSMulticastClient();
		client.test();
		
		// Connector threads run as daemons so wait in main thread until handshake is done
		synchronized (ExampleDTLSMulticastClient.class) {
			ExampleDTLSMulticastClient.class.wait();
		}
	}
}
