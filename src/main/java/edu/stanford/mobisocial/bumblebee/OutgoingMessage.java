package edu.stanford.mobisocial.bumblebee;

public interface OutgoingMessage {
	public String toPublicKey();
	public String contents();
}