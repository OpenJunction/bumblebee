package edu.stanford.mobisocial.bumblebee;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface TransportIdentityProvider {
	public PublicKey userPublicKey();
	public PrivateKey userPrivateKey();
	public String userPersonId();
	public PublicKey publicKeyForPersonId(String id);
	public String personIdForPublicKey(PublicKey key);
}
