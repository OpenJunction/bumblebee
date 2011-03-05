package edu.stanford.mobisocial.bumblebee;

import java.security.PublicKey;

public interface OutgoingMessage {
	public PublicKey toPublicKey();

	public String contents();
}
