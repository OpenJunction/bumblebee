package edu.stanford.mobisocial.bumblebee;
import java.security.*;
import javax.crypto.*;

public class StandardIdentity implements Identity{

	private PublicKey pubkey;
	private PrivateKey privkey;

    public StandardIdentity(PublicKey pubkey, PrivateKey privkey){
		this.pubkey = pubkey;
		this.privkey = privkey;
	}

    public PublicKey publicKey(){
		return pubkey;
	}

    public String prepareOutgoingMessage(String s, PublicKey receiver) throws EncryptionFailedException {
		try{
			byte[] plain = s.getBytes("UTF8");

			Signature signature = Signature.getInstance("SHA1withRSA", "BC");
			signature.initSign(privkey, new SecureRandom());
			signature.update(plain);
			byte[] sigBytes = signature.sign();
			System.out.println("Computed signature of length " + sigBytes.length);

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, receiver);
			byte[] cipherData = cipher.doFinal(plain);
			System.out.println("Computed cipher of length " + cipherData.length);

			byte[] pkeyBytes = pubkey.getEncoded();
			System.out.println("Public key of length " + pkeyBytes.length);

			return (new String(pkeyBytes, "UTF8") + "," + 
					new String(sigBytes, "UTF8") + "," + 
					new String(cipherData, "UTF8"));

		}catch(Exception e){
			throw new EncryptionFailedException();
		}
	}
	
}