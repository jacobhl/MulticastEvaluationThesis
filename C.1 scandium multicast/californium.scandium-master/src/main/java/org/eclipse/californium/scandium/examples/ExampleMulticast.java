package org.eclipse.californium.scandium.examples;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;

public class ExampleMulticast {
	public static final int DEFAULT_MULTICAST_PORT = 11001;
	public static final String multicastGroup = "224.224.224.224";
	public static final String adapterName = "localhost";
	public static final int MAX_PACKET_SIZE = 65507;

	CharBuffer charBuffer = null;
	Charset charset = Charset.defaultCharset();
	CharsetDecoder decoder = charset.newDecoder();
	static ByteBuffer message = ByteBuffer.allocateDirect(MAX_PACKET_SIZE);
	static boolean loop = true;

	static byte[] buffer = new byte[MAX_PACKET_SIZE];

	public static void main(String[] args) {

	    try {


	        MulticastSocket mSocket = new MulticastSocket(DEFAULT_MULTICAST_PORT);
	        mSocket.setReuseAddress(true);
	        //mSocket.setSoTimeout(5000);

	        mSocket.joinGroup(new InetSocketAddress(multicastGroup, DEFAULT_MULTICAST_PORT),NetworkInterface.getByName(adapterName));

	        DatagramPacket p = new DatagramPacket(buffer, MAX_PACKET_SIZE);
	        while (loop){
	            try{
	                mSocket.receive(p);
	                System.out.println("Packet Received.");
	            } catch (SocketTimeoutException ex){
	                System.out.println("Socket Timed out");
	            }
	        }

	    } catch (IOException ex){
	        System.err.println(ex);
	    }

	}
}
