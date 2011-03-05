package edu.stanford.mobisocial.bumblebee;
import java.security.PublicKey;

public interface Identity {
	public PublicKey publicKey();
	public String prepareOutgoingMessage(String s, PublicKey receiver) throws EncryptionFailedException ;
}