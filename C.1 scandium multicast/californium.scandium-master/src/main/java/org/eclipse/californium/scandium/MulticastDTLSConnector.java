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
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.ConnectorBase;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.ApplicationMessage;
import org.eclipse.californium.scandium.dtls.ApplicationMessageMulticast;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSFlight;
import org.eclipse.californium.scandium.dtls.DTLSMessage;
import org.eclipse.californium.scandium.dtls.DTLSMulticastFlight;
import org.eclipse.californium.scandium.dtls.DTLSMulticastMessage;
import org.eclipse.californium.scandium.dtls.DTLSMulticastSession;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.FragmentedHandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordMulticast;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHello;
import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * A {@link Connector} implementation for securing the inner datagrams using the DTLS standard.	
 * 
 */
public class MulticastDTLSConnector extends ConnectorBase {
	/*
	 * Note: DTLSConnector can also implement the interface Connector instead of
	 * extending ConnectorBase
	 */
	
	private final static Logger LOGGER = Logger.getLogger(MulticastDTLSConnector.class.getCanonicalName());

	/** all the configuration options for the DTLS connector */ 
	private final MulticastDTLSConnectorConfig config = new MulticastDTLSConnectorConfig(this);
	
	private final InetSocketAddress address;
	
	private MulticastSocket socket;
	private byte[] aesKey;
	private byte[] client_iv;
	private int multicastID;
	
	/** The timer daemon to schedule retransmissions. */
	private Timer timer = new Timer(true); // run as daemon
	
	/** Storing sessions according to peer-addresses */
	private Map<String, DTLSMulticastSession> dtlsMulticastSessions = new ConcurrentHashMap<String, DTLSMulticastSession>();

	/** Storing handshakers according to peer-addresses. */
	private Map<String, Handshaker> handshakers = new ConcurrentHashMap<String, Handshaker>();

	/** Storing flights according to peer-addresses. */
	private Map<String, DTLSMulticastFlight> flights = new ConcurrentHashMap<String, DTLSMulticastFlight>();
	
	/** root authorities certificates */
	private final Certificate[] rootCerts;
	
	/** defines if connector is multicast or not **/
	private boolean isMulticast;
	
	/**
	 * Create a DTLS connector.
	 * @param address the address to bind
	 * @param rootCertificates list of trusted self-signed root certificates
	 */
	public MulticastDTLSConnector(InetSocketAddress address, Certificate[] rootCertificates) {
		super(address);
		this.address = address;
		this.rootCerts = rootCertificates;


	}
	
	public void SetKey(byte[] AES, byte[] IV)
	{
		this.aesKey = AES;
		this.client_iv = IV;
	}
	
	public void SetMulticastID(int id)
	{this.multicastID = id;}
	
	/**
	 * Close the DTLS session with all peers.
	 */
	public void close() {
		for (DTLSMulticastSession session : dtlsMulticastSessions.values()) {
			this.close(session.getPeer());
		}
	}
	
	/**
	 * Close the DTLS session with the given peer.
	 * 
	 * @param peerAddress the remote endpoint of the session to close
	 */
	public void close(InetSocketAddress peerAddress) {
	   String addrKey = addressToKey(peerAddress); 
		try {
			DTLSMulticastSession session = dtlsMulticastSessions.get(addrKey);
			
			if (session != null) {

			} else {
				if (LOGGER.isLoggable(Level.WARNING)) {
					LOGGER.warning("Session to close not found: " + peerAddress.toString());
				}
			}
		} finally {
			//clear sessions
			dtlsMulticastSessions.remove(addrKey);
			handshakers.remove(addrKey);
			flights.remove(addrKey);
		}
	}
	
	@Override
	public synchronized void start() throws IOException {
		//socket = new DatagramSocket(address.getPort(), address.getAddress());
		socket = new MulticastSocket(address.getPort());
		socket.setReuseAddress(true);
		socket.joinGroup(new InetSocketAddress(address.getAddress(), address.getPort()),NetworkInterface.getByName("localhost")); //localhost
		super.start();
		if (LOGGER.isLoggable(Level.INFO)) {
			LOGGER.info("DLTS connector listening on "+address);
		}
	}
	
	@Override
	public synchronized void stop() {
		this.close();
		this.socket.close();
		super.stop();
	}
	
	// TODO: We should not return null
	@Override
	protected RawData receiveNext() throws Exception {
		byte[] buffer = new byte[config.getMaxPayloadSize()];
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
		
		socket.receive(packet);
		
		
		if (packet.getLength() == 0)
			return null;

		InetSocketAddress peerAddress = new InetSocketAddress(packet.getAddress(), packet.getPort());

		if (LOGGER.isLoggable(Level.FINEST)) {
			LOGGER.finest(" => find handshaker for key "+peerAddress.toString());
		}
		//DTLSSession session = dtlsSessions.get(addressToKey(peerAddress));
		DTLSMulticastSession session = new DTLSMulticastSession(new InetSocketAddress("10.192.41.99", 5684), true); // Gør det noget?
		//DTLSSession session = new DTLSSession(new InetSocketAddress("192.168.1.5", 5684), true);
		//DTLSSession session = new DTLSSession(new InetSocketAddress("192.168.1.134", 5684), true);
		
		session.setCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		
		
		SecretKey key = new SecretKeySpec(aesKey, "AES");
		
		session.getReadState().setIv(new IvParameterSpec(client_iv));
		session.getReadState().setCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		session.getReadState().setEncryptionKey(key);
		
		Handshaker handshaker = handshakers.get(addressToKey(peerAddress));
		byte[] data = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength());

		try {
			List<RecordMulticast> records = RecordMulticast.fromByteArray(data);

			for (RecordMulticast record : records) {
				record.setSession(session);

				RawData raw = null;

				ContentType contentType = record.getType();
				LOGGER.finest(" => contentType: "+contentType);
				DTLSMulticastFlight flight = null;
				switch (contentType) {
				case APPLICATION_DATA:
					if (session == null) {
						// There is no session available, so no application data
						// should be received, discard it
						if (LOGGER.isLoggable(Level.INFO)) {
							LOGGER.info("Discarded unexpected application data message from " + peerAddress.toString());
						}
						return null;
					}
					// at this point, the current handshaker is not needed
					// anymore, remove it
					handshakers.remove(addressToKey(peerAddress));

					ApplicationMessageMulticast applicationData = (ApplicationMessageMulticast) record.getFragment();
					raw = new RawData(applicationData.getData());
					break;

				case ALERT:
				case CHANGE_CIPHER_SPEC:
				case HANDSHAKE:
					break;

				default:
					LOGGER.severe("Received unknown DTLS record from " + peerAddress.toString() + ":\n" + ByteArrayUtils.toHexString(data));
					break;
				}

				if (flight != null) {
					cancelPreviousFlight(peerAddress);

					flight.setPeerAddress(peerAddress);
					flight.setSession(session);

					if (flight.isRetransmissionNeeded()) {
						flights.put(addressToKey(peerAddress), flight);
						scheduleRetransmission(flight);
					}

					sendFlight(flight);
				}

				if (raw != null) {

					raw.setAddress(packet.getAddress());
					raw.setPort(packet.getPort());

					return raw;
				}
			}

		} catch (Exception e) {
			/*
			 * If it is a known handshake failure, send the specific Alert,
			 * otherwise the general Handshake_Failure Alert. 
			 */
			DTLSMulticastFlight flight = new DTLSMulticastFlight();
			flight.setRetransmissionNeeded(false);
			flight.setPeerAddress(peerAddress);
			flight.setSession(session);
			
			AlertMessage alert;
			if (e instanceof HandshakeException) {
				alert = ((HandshakeException) e).getAlert();
				LOGGER.severe("Handshake Exception (" + peerAddress.toString() + "): " + e.getMessage()+" we close the session");
				close(session.getPeer());
			} else {
				alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
				LOGGER.log(Level.SEVERE, "Unknown Exception (" + peerAddress + ").", e);
			}

			LOGGER.log(Level.SEVERE, "Datagram which lead to exception (" + peerAddress + "): " + ByteArrayUtils.toHexString(data), e);
			
			if (session == null) {
				// if the first received message failed, no session has been set
				session = new DTLSMulticastSession(peerAddress, false);
			}
			cancelPreviousFlight(peerAddress);
			
			sendFlight(flight);
		} // receive()
		return null;
	}

	@Override
	protected void sendNext(RawData message) throws Exception {
		
		InetSocketAddress peerAddress = message.getInetSocketAddress();
		if (LOGGER.isLoggable(Level.FINE)) {
			LOGGER.fine("Sending message: " + new String(message.getBytes()) + " to: " + peerAddress);
		}
		DTLSMulticastSession session = dtlsMulticastSessions.get(addressToKey(peerAddress));
		
		RecordMulticast encryptedMessage = null;
		Handshaker handshaker = null;


		session = new DTLSMulticastSession(peerAddress, true);
		session.setCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		//byte[] aesKey = new byte[]{(byte) 0xC9, 0x0E, 0x6A, (byte) 0xA2, (byte) 0xEF, 0x60, 0x34, (byte) 0x96,
		//	(byte) 0x90, 0x54, (byte) 0xC4, (byte) 0x96, 0x65, (byte) 0xBA, 0x03, (byte) 0x9E};
		//byte[] client_iv = new byte[]{0x55, 0x23, 0x2F, (byte) 0xA3};
		
		SecretKey key = new SecretKeySpec(aesKey, "AES");
		
		session.getWriteState().setIv(new IvParameterSpec(client_iv));
		session.getWriteState().setCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		session.getWriteState().setEncryptionKey(key);
		
		dtlsMulticastSessions.put(addressToKey(peerAddress), session);	
		DTLSMulticastMessage fragment = new ApplicationMessageMulticast(message.getBytes());
		//tilføj ID
		encryptedMessage = new RecordMulticast(ContentType.APPLICATION_DATA, session.getWriteEpoch(), multicastID, session.getSequenceNumber(), fragment, session);
		DTLSMulticastFlight flight = new DTLSMulticastFlight();

		// the CoAP message has been encrypted and can be sent to the peer
		if (encryptedMessage != null) {
			flight.addMessage(encryptedMessage);
		}
		
		flight.setPeerAddress(peerAddress);
		flight.setSession(session);
		sendFlight(flight);
	}

	/**
	 * Returns the {@link DTLSSession} related to the given peer address.
	 * 
	 * @param address the peer address
	 * @return the {@link DTLSSession} or <code>null</code> if no session found.
	 */
	public DTLSMulticastSession getSessionByAddress(InetSocketAddress address) {
		if (address == null) {
			return null;
		}
		return dtlsMulticastSessions.get(addressToKey(address));
	}

	/**
	 * Searches through all stored sessions and returns that session which
	 * matches the session identifier or <code>null</code> if no such session
	 * available. This method is used when the server receives a
	 * {@link ClientHello} containing a session identifier indicating that the
	 * client wants to resume a previous session. If a matching session is
	 * found, the server will resume the session with a abbreviated handshake,
	 * otherwise a full handshake (with new session identifier in
	 * {@link ServerHello}) is conducted.
	 * 
	 * @param sessionID
	 *            the client's session identifier.
	 * @return the session which matches the session identifier or
	 *         <code>null</code> if no such session exists.
	 */
	private DTLSMulticastSession getSessionByIdentifier(byte[] sessionID) {
		if (sessionID == null) {
			return null;
		}
		
		for (Entry<String, DTLSMulticastSession> entry : dtlsMulticastSessions.entrySet()) {
			// FIXME session identifiers may not be set, when the handshake failed after the initial message
			// these sessions must be deleted when this happens
			try {
				byte[] id = entry.getValue().getSessionIdentifier().getSessionId();
				if (Arrays.equals(sessionID, id)) {
					return entry.getValue();
				}
			} catch (Exception e) {
				continue;
			}
		}
		
		for (DTLSMulticastSession session:dtlsMulticastSessions.values()) {
			try {
				byte[] id = session.getSessionIdentifier().getSessionId();
				if (Arrays.equals(sessionID, id)) {
					return session;
				}
			} catch (Exception e) {
				continue;
			}
		}
		
		return null;
	}
	
	private void sendFlight(DTLSMulticastFlight flight) {
		byte[] payload = new byte[] {};
		
		// put as many records into one datagram as allowed by the block size
		List<DatagramPacket> datagrams = new ArrayList<DatagramPacket>();

		for (RecordMulticast record : flight.getMessages()) {
			if (flight.getTries() > 0) {
				// adjust the record sequence number
				int epoch = record.getEpoch();
				record.setSequenceNumber(flight.getSession().getSequenceNumber(epoch));
			}
			
			byte[] recordBytes = record.toByteArray();
			if (payload.length + recordBytes.length > config.getMaxPayloadSize()) {
				// can't add the next record, send current payload as datagram
				DatagramPacket datagram = new DatagramPacket(payload, payload.length, flight.getPeerAddress().getAddress(), flight.getPeerAddress().getPort());
				datagrams.add(datagram);
				payload = new byte[] {};
			}

			// retrieve payload
			payload = ByteArrayUtils.concatenate(payload, recordBytes);
		}
		DatagramPacket datagram = new DatagramPacket(payload, payload.length, flight.getPeerAddress().getAddress(), flight.getPeerAddress().getPort());
		datagrams.add(datagram);

		// send it over the UDP socket
		try {
			for (DatagramPacket datagramPacket : datagrams) {
				socket.send(datagramPacket);
			}
			
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "Could not send the datagram", e);
		}
	}
	
	private void handleTimeout(DTLSMulticastFlight flight) {

		// set DTLS retransmission maximum
		final int max = config.getMaxRetransmit();

		// check if limit of retransmissions reached
		if (flight.getTries() < max) {

			flight.incrementTries();

			sendFlight(flight);

			// schedule next retransmission
			scheduleRetransmission(flight);

		} else {
			LOGGER.fine("Maximum retransmissions reached.");
		}
	}

	private void scheduleRetransmission(DTLSMulticastFlight flight) {

		// cancel existing schedule (if any)
		if (flight.getRetransmitTask() != null) {
			flight.getRetransmitTask().cancel();
		}
		
		if (flight.isRetransmissionNeeded()) {
			// create new retransmission task
			flight.setRetransmitTask(new RetransmitTask(flight));
	
			// calculate timeout using exponential back-off
			if (flight.getTimeout() == 0) {
				// use initial timeout
				flight.setTimeout(config.getRetransmissionTimeout());
			} else {
				// double timeout
				flight.incrementTimeout();
			}
	
			// schedule retransmission task
			timer.schedule(flight.getRetransmitTask(), flight.getTimeout());
		}
	}
	
	/**
	 * Cancels the retransmission timer of the previous flight (if available).
	 * 
	 * @param peerAddress
	 *            the peer's address.
	 */
	private void cancelPreviousFlight(InetSocketAddress peerAddress) {
		DTLSMulticastFlight previousFlight = flights.get(addressToKey(peerAddress));
		if (previousFlight != null) {
			previousFlight.getRetransmitTask().cancel();
			previousFlight.setRetransmitTask(null);
			flights.remove(addressToKey(peerAddress));
		}
	}

	@Override
	public String getName() {
		return "DTLS";
	}

	public InetSocketAddress getAddress() {
		if (socket == null) return getLocalAddr();
		else return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
	}
	
	private class RetransmitTask extends TimerTask {

		private DTLSMulticastFlight flight;

		RetransmitTask(DTLSMulticastFlight flight2) {
			this.flight = flight2;
		}

		@Override
		public void run() {
			handleTimeout(flight);
		}
	}
	
	private String addressToKey(InetSocketAddress address) {
		return address.toString().split("/")[1];
	}


    public MulticastDTLSConnectorConfig getConfig() {
        return config;
    }
}
