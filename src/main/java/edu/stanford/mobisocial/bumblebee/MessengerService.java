package edu.stanford.mobisocial.bumblebee;

import java.util.*;

public abstract class MessengerService {
	private Set<StateListener> stateListeners = new HashSet<StateListener>();
	private Set<MessageListener> messageListeners = new HashSet<MessageListener>();
	private Set<ConnectionStatusListener> statusListeners = new HashSet<ConnectionStatusListener>();
	private final TransportIdentityProvider mIdent;
    private final ConnectionStatus mConnectionStatus;

	public MessengerService(TransportIdentityProvider ident, ConnectionStatus status) {
		this.mIdent = ident;
        this.mConnectionStatus = status;
	}

	protected TransportIdentityProvider identity() {
		return mIdent;
	}

	protected ConnectionStatus connectionStatus() {
		return mConnectionStatus;
	}

	public abstract void init();

	public abstract void sendMessage(OutgoingMessage m);

	//Do these all need to be synchronized... we definitely have threads roaming about...?
	public void addStateListener(StateListener l) {
		stateListeners.add(l);
	}

	public void addMessageListener(MessageListener l) {
		messageListeners.add(l);
	}

	public void addConnectionStatusListener(ConnectionStatusListener l) {
		statusListeners.add(l);
	}

	public void removeStateListener(StateListener l) {
		stateListeners.remove(l);
	}

	public void removeMessageListener(MessageListener l) {
		messageListeners.remove(l);
	}

	public void removeStatusListener(ConnectionStatus l) {
		statusListeners.remove(l);
	}

	protected void signalReady() {
		for (StateListener l : stateListeners) {
			l.onReady();
		}
	}

	protected void signalNotReady() {
		for (StateListener l : stateListeners) {
			l.onNotReady();
		}
	}

	protected void signalConnectionStatus(String msg, Exception e) {
		for (ConnectionStatusListener l : statusListeners) {
			l.onStatus(msg, e);
		}
	}

	protected void signalMessageReceived(IncomingMessage m) {
		for (MessageListener l : messageListeners) {
			l.onMessage(m);
		}
	}
}
