package edu.stanford.mobisocial.bumblebee;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

public interface OutgoingMessage {
	public List<RSAPublicKey> toPublicKeys();
	public String contents();
	public void onEncoded(byte[] encoded);
	public byte[] getEncoded();
	public void onCommitted();
	public long getLocalUniqueId();
	
}
