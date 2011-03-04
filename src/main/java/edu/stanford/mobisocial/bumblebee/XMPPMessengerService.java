package edu.stanford.mobisocial.bumblebee;
import org.jivesoftware.smack.*;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.filter.PacketFilter;
import java.util.*;
import java.util.concurrent.*;

public class XMPPMessengerService extends MessengerService{

	private XMPPConnection connection = null;
	private String username = null;
	private String password = null;
	private LinkedBlockingQueue<OutgoingMessage> sendQ = new LinkedBlockingQueue<OutgoingMessage>();

	private Thread sendWorker = new Thread(){
			@Override
			public void run(){
				while(true){
					try{
						OutgoingMessage m = sendQ.peek();
						if(m != null && connected()){
							System.out.println("Pulled message off sendQueue. Sending.");
							sendQ.poll();
							String plain = m.contents();
							String cypher = identity().encrypt(plain);
							Message msg = new Message(cypher);
							msg.setFrom(username);
							msg.setTo(publicKeyToUsername(m.toPublicKey()));
							connection.sendPacket(msg);
						}
						else{
							Thread.sleep(1000);
						}
					}
					catch(InterruptedException e){}
				}
			}
		};

	public XMPPMessengerService(Identity ident){
		super(ident);
		username = publicKeyToUsername(ident.publicKey());
		password = username + "pass";
		sendWorker.start();
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
				handleLoggedIn();
			}
			catch(XMPPException e){
				try{
					System.out.println("Login failed. Attempting to create account..");
					mgr.createAccount(username, password, atts);
					System.out.println("Account created, logging in...");
					try{
						connection.login(username, password);
						System.out.println("Logged in!");
						handleLoggedIn();
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

	private void handleLoggedIn(){
		assertConnected();
		connection.addPacketListener(new PacketListener(){
				public void processPacket(final Packet p){
					if(p instanceof Message){
						final Message m = (Message)p;
						signalMessageReceived(new IncomingMessage(){
								public String from(){
									return m.getFrom();
								}
								public String contents(){
									return m.getBody();
								}
								public String toString(){ 
									return contents();
								}
							});
					}
					else{
						System.out.println("Unrecognized packet " + p.toString());
					}
				}
			}, 
			new PacketFilter(){
				public boolean accept(Packet p){
					return true;
				}
			}
			);
		signalReady();
	}

	private boolean connected(){
		return connection != null && connection.isConnected();
	}

	private void assertConnected(){
		if(!connected()) throw new IllegalStateException("Not connected!");
	}

	@Override
	public void sendMessage(OutgoingMessage m){
		sendQ.offer(m);
	}

}