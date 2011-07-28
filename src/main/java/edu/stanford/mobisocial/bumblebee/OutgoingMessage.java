package edu.stanford.mobisocial.bumblebee;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public interface OutgoingMessage {
	public List<RSAPublicKey> toPublicKeys();
	public String contents();
	public void onCommitted();
}
