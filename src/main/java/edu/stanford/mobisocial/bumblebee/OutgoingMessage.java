package edu.stanford.mobisocial.bumblebee;
import java.security.PublicKey;
import java.util.List;

public interface OutgoingMessage {
	public List<PublicKey> toPublicKeys();
	public String contents();
}
