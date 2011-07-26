package edu.stanford.mobisocial.bumblebee;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface TransportIdentityProvider {
	public RSAPublicKey userPublicKey();
	public RSAPrivateKey userPrivateKey();
	public String userPersonId();
	public RSAPublicKey publicKeyForPersonId(String id);
	public String personIdForPublicKey(RSAPublicKey key);
}
