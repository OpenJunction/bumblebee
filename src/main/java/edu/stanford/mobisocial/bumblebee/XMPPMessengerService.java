package edu.stanford.mobisocial.bumblebee;
import org.jivesoftware.smack.*;
import org.jivesoftware.smack.packet.Message;
import java.util.*;

public class XMPPMessengerService extends MessengerService{

	private XMPPConnection connection = null;
	private String username = null;
	private String password = null;

	public XMPPMessengerService(Identity ident){
		super(ident);
		username = publicKeyToUsername(ident.publicKey());
		password = username + "pass";
	}

	private String publicKeyToUsername(String pkey){
		String me = null;
		try{
			me = Util.SHA1(pkey);
		}
		catch(Exception e){
			throw new IllegalArgumentException("Could not compute SHA1 of public key.");
		}
		return me.substring(0,10);
	}

	@Override
	public void init(){
		if(username == null || password == null){
			throw new IllegalArgumentException("Must supply username and password.");
		}
		try{
			connection = new XMPPConnection("sb.openjunction.org");
			connection.connect();
			AccountManager mgr = connection.getAccountManager();
			Map<String,String> atts = new HashMap<String,String>();
			atts.put("name", "AnonUser");
			atts.put("email", "AnonUser@prpl.stanford.edu");
			try{
				connection.login(username, password);
				System.out.println("Logged in!");
				signalReady();
			}
			catch(XMPPException e){
				try{
					System.out.println("Login failed. Attempting to create account..");
					mgr.createAccount(username, password, atts);
					System.out.println("Account created, logging in...");
					connection = new XMPPConnection("sb.openjunction.org");
					connection.connect();
					try{
						connection.login(username, password);
						System.out.println("Logged in!");
						signalReady();
					}
					catch(XMPPException ex){
						System.err.println("Login failed.");
						System.err.println(ex);
					}
				}
				catch(XMPPException ex){
					System.err.println("User account creation failed due to: ");
					System.err.println(ex);
				}
			}
		}
		catch (XMPPException e) {
			Throwable ex = e.getWrappedThrowable();
			ex.printStackTrace(System.err);
		}
	}

	private boolean connected(){
		return connection != null && connection.isConnected();
	}

	private void assertConnected(){
		if(!connected()) throw new IllegalStateException("Not connected!");
	}

	@Override
	public void sendMessage(OutgoingMessage m){
		assertConnected();
		String plain = m.contents();
		String cypher = identity().encrypt(plain);
		Message msg = new Message(cypher);
		msg.setFrom(username);
		msg.setTo(publicKeyToUsername(m.toPublicKey()));
		connection.sendPacket(msg);
	}

}