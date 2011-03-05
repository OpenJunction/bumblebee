package edu.stanford.mobisocial.bumblebee;

import edu.stanford.mobisocial.bumblebee.util.*;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;

public class StandardIdentity implements Identity {
	private PublicKey pubkey;
	private PrivateKey privkey;

	public StandardIdentity(PublicKey pubkey, PrivateKey privkey) {
		this.pubkey = pubkey;
		this.privkey = privkey;
	}

	public PublicKey publicKey() {
		return pubkey;
	}

	public PublicKey getMessagePublicKey(String s) {
		try {
			String[] parts = s.split(",");
			String keyS = parts[0];
			byte[] keyBytes = Base64.decode(keyS);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");

			return kf.generatePublic(spec);
		} catch (Exception e) {
			e.printStackTrace(System.err);

			return null;
		}
	}

	public String prepareIncomingMessage(String s, PublicKey sender) {
		try {
			String[] parts = s.split(",");
			String sigS = parts[1];
			byte[] sigBytes = Base64.decode(sigS);
			String ciphS = parts[2];
			byte[] ciphBytes = Base64.decode(ciphS);

			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(sender);
			signature.update(ciphBytes);

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privkey);

			byte[] cipherData = cipher.doFinal(ciphBytes);

			System.out.println("Cipher-text signature verified: "
					+ signature.verify(sigBytes));

			return new String(cipherData, "UTF8");
		} catch (Exception e) {
			e.printStackTrace(System.err);

			return null;
		}
	}

	public String prepareOutgoingMessage(String s, PublicKey toPubKey)
			throws CryptoException {
		try {
			byte[] plain = s.getBytes("UTF8");

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, toPubKey);

			byte[] cipherData = cipher.doFinal(plain);
			System.out
					.println("Computed cipher of length " + cipherData.length);

			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privkey, new SecureRandom());
			signature.update(cipherData);

			byte[] sigBytes = signature.sign();
			System.out.println("Computed signature of length "
					+ sigBytes.length);

			byte[] pkeyBytes = pubkey.getEncoded();
			System.out.println("Public key of length " + pkeyBytes.length);

			return (Base64.encodeToString(pkeyBytes, false) + ","
					+ Base64.encodeToString(sigBytes, false) + "," + Base64
					.encodeToString(cipherData, false));
		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new CryptoException();
		}
	}
}
