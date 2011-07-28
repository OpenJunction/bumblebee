package edu.stanford.mobisocial.bumblebee;
import edu.stanford.mobisocial.bumblebee.util.Base64;
import org.jivesoftware.smack.filter.PacketTypeFilter;
import org.jivesoftware.smack.*;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Packet;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.*;
import org.jivesoftware.smack.packet.PacketExtension;

public class XMPPMessengerService extends MessengerService {

	public static final String XMPP_SERVER = "prpl.stanford.edu";
	public static final int XMPP_PORT = 5222;

	private XMPPConnection mConnection = null;
	private MessageFormat mFormat = null;
	private String mUsername = null;
	private String mPassword = null;
	private LinkedBlockingQueue<OutgoingMessage> mSendQ = 
        new LinkedBlockingQueue<OutgoingMessage>();

	private Thread sendWorker = new Thread() {
            @Override
            public void run() {
                while (true) {
                    try {
                        OutgoingMessage m = mSendQ.peek();
                        if (connectedToInternet() && (m != null) && connected()) {
                            mSendQ.poll();
                            String plain = m.contents();
                            try {
                                XEP0033Header header = new XEP0033Header();
                                for(RSAPublicKey pubKey : m.toPublicKeys()){
                                    String jid = identity().personIdForPublicKey(pubKey) 
                                        + "@" + XMPP_SERVER;
                                    header.addAddress("to", jid);
                                }
                                byte[] cyphered = mFormat.encodeOutgoingMessage(
                                    plain, m.toPublicKeys());
                                String msgText = Base64.encodeToString(cyphered, false);
                                Message msg = new Message();
                                msg.setFrom(mUsername + "@" + XMPP_SERVER);
                                msg.setBody(msgText);
                                msg.setTo(XMPP_SERVER);
                                msg.addExtension(header);
                                mConnection.sendPacket(msg);
                                m.onCommitted();
                            } catch (CryptoException e) {
                                e.printStackTrace(System.err);
                            }
                        } 
                        else {
                            if(connectedToInternet() && !connected()){
                                System.out.println("Oops! Not connected. Trying to connect....");
                                reconnect();
                            }
                            Thread.sleep(1000);
                        }
                    } catch (InterruptedException e) {
                    }
                }
            }
        };

	public XMPPMessengerService(TransportIdentityProvider ident, ConnectionStatus status) {
		super(ident, status);
		mUsername = ident.userPersonId();
		mPassword = mUsername + "pass";
		sendWorker.start();
        mFormat = new MessageFormat(ident);
	}

    private class XEP0033Header implements PacketExtension{
        List<String> addresses = new ArrayList<String>();
        public void addAddress(String type, String jid){
            addresses.add("<address type=\"" + type + "\" jid=\"" + jid + "\" />");
        }
        public String getElementName(){ return "addresses";}
        public String getNamespace(){ return "http://jabber.org/protocol/address";}
        public String toXML(){
            String xml = "<" + getElementName() + " xmlns=\"" + 
                getNamespace() +  "\">";
            for(String a : addresses){
                xml += a;
            }
            xml += "</" + getElementName() + ">";
            return xml;
        }
    }

    synchronized private void reconnect(){
		if ((mUsername == null) || (mPassword == null)) {
			throw new IllegalArgumentException(
                "Must supply username and password.");
		}

        try{
            if(mConnection != null){
                mConnection.disconnect();
            }
        }
        catch(Exception e){}

		try {
			mConnection = newConnection();
            System.out.println("Connecting...");
			mConnection.connect();
            addHandlers(mConnection);

			AccountManager mgr = mConnection.getAccountManager();
			Map<String, String> atts = new HashMap<String, String>();
			atts.put("name", "AnonUser");
			atts.put("email", "AnonUser@" + XMPP_SERVER);
			try {
                System.out.println("Logging in with " + mUsername + " " + mPassword);
				mConnection.login(mUsername, mPassword);
				System.out.println("Logged in!");
				signalReady();
			} catch (XMPPException e) {
				try {
					System.out
                        .println("Login failed. Attempting to create account..");
					mgr.createAccount(mUsername, mPassword, atts);
					System.out.println("Account created, logging in...");
                    removeHandlers(mConnection);
                    mConnection.disconnect();

                    mConnection = newConnection();
                    mConnection.connect();
                    addHandlers(mConnection);
					try {
						mConnection.login(mUsername, mPassword);
						System.out.println("Logged in!");
                        signalReady();
					} catch (XMPPException ex) {
						System.err.println("Login failed.");
                        ex.printStackTrace(System.err);
					}
				} catch (XMPPException ex) {
					System.err.println("User account creation failed due to: ");
                    ex.printStackTrace(System.err);
				}
			}
		} catch (Exception ex) {
            System.err.println("XMPPMessengerService: Reconnect failed.");
			ex.printStackTrace(System.err);
		}
    }

    protected XMPPConnection newConnection(){
        ConnectionConfiguration conf = 
            new ConnectionConfiguration(XMPP_SERVER, XMPP_PORT);
        conf.setReconnectionAllowed(false);
        return new XMPPConnection(conf); 
    }

	@Override
	synchronized public void init() {
        if(!sendWorker.isAlive())
            sendWorker.start();
	}

    private ConnectionListener mConnListener = new ConnectionListener() {
            public void connectionClosed() {
                System.out.println("Connection closed");
            }

            public void connectionClosedOnError(Exception e) {
                System.out.println("Connection closed on error: " + e);
            }

            public void reconnectingIn(int i) {
                System.out.println("Reconnecting in: " + i);
            }

            public void reconnectionFailed(Exception e) {
                System.out.println("Reconnection failed: " + e);
            }

            public void reconnectionSuccessful() {
                System.out.println("Reconnection successful");
            }
        };

    private PacketListener mPacketListener = new PacketListener() {
            public void processPacket(final Packet p) {
                try{
                    final Message m = (Message) p;
                    final String jid = m.getFrom();
                    final byte[] body = Base64.decode(m.getBody());
                    if(body == null) throw new RuntimeException("Could not decode message.");

                    String id = mFormat.getMessagePersonId(body);
                    if (id == null || !(jid.startsWith(id))) {
                        System.err.println("WTF! person id in message does not match sender!.");
                        return;
                    }
                    RSAPublicKey pubKey = identity().publicKeyForPersonId(id);
                    if (pubKey == null) {
                        System.err.println("WTF! message from unrecognized sender! " + id);
                        return;
                    }
                    try{
                        final String contents = mFormat.decodeIncomingMessage(body);
                        int i = jid.indexOf("@");
                        final String from = i > -1 ? jid.substring(0, i) : jid;
                        signalMessageReceived(
                            new IncomingMessage() {
                                public String from() { return from; }
                                public String contents() { return contents; }
                                public String toString() { return contents(); }
                            });
                    }
                    catch(CryptoException e){
                        System.err.println("Failed in processing incoming message! Reason:");
                        e.printStackTrace(System.err);
                    }
                }
                catch(Exception e){
                    System.err.println("Error handling incoming message. Reason:");
                    e.printStackTrace(System.err);                    
                }
            }
        };

	private void addHandlers(XMPPConnection conn) {
		conn.addConnectionListener(mConnListener);
		conn.addPacketListener(mPacketListener, new PacketTypeFilter(Message.class));
	}

	private void removeHandlers(XMPPConnection conn) {
		conn.removeConnectionListener(mConnListener);
		conn.removePacketListener(mPacketListener);
	}

	private boolean connected() {
		return (mConnection != null) && mConnection.isConnected();
	}

	private boolean connectedToInternet() {
		return connectionStatus().isConnected();
	}

	private void assertConnected() {
		if (!connected()) {
			throw new IllegalStateException("Not connected!");
		}
	}

	@Override
	public void sendMessage(OutgoingMessage m) {
		mSendQ.offer(m);
	}
}
