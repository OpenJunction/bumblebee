package edu.stanford.mobisocial.bumblebee;

import java.security.PublicKey;

public interface Identity {
	public PublicKey publicKey();

	public PublicKey getMessagePublicKey(String s);

	public String prepareIncomingMessage(String s, PublicKey sender);

	public String prepareOutgoingMessage(String s, PublicKey receiver)
			throws CryptoException;
}
