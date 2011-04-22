package edu.stanford.mobisocial.bumblebee;
import edu.stanford.mobisocial.bumblebee.util.*;
import java.security.*;
import java.util.Arrays;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;

import javax.crypto.*;

public class XMPPMessageFormat {

    public static final int AES_Key_Size = 128;
    private TransportIdentityProvider mIdent;

	public XMPPMessageFormat(TransportIdentityProvider ident) {
        mIdent = ident;
	}

	public String getMessagePersonId(String s) {
        try{
            int sep = s.indexOf(",");
            if(sep == -1){ return null; }
            byte[] bodyBytes = Base64.decode(s.substring(sep + 1));
            ObjectInputStream in = new ObjectInputStream(
                new ByteArrayInputStream(bodyBytes));
            short len = in.readShort();
            byte[] idBytes = new byte[len];
            in.readFully(idBytes);
            return new String(idBytes, "UTF8");
        }catch(UnsupportedEncodingException e){ e.printStackTrace(System.err); return null; }
        catch(IOException e){ e.printStackTrace(System.err); return null; }
	}


	public String prepareIncomingMessage(String s, PublicKey sender) throws CryptoException{
		try {
            int sep = s.indexOf(",");
            if(sep == -1){throw new CryptoException("No tag seperator.");}
            byte[] sigBytes = Base64.decode(s.substring(0, sep));
            byte[] bodyBytes = Base64.decode(s.substring(sep + 1));

            Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initVerify(sender);
            signature.update(bodyBytes);
            boolean status = signature.verify(sigBytes);
            if(!status){throw new CryptoException("Failed to verify signature.");}

            ByteArrayInputStream bi = new ByteArrayInputStream(bodyBytes);
            ObjectInputStream in = new ObjectInputStream(bi);

            short fromPidLen = in.readShort();
            in.skipBytes(fromPidLen);

			byte[] userPidBytes = mIdent.userPersonId().getBytes("UTF8");            

            short numKeys = in.readShort();
            byte[] keyBytesE = null;
            for(int i = 0; i < numKeys; i++){
                short idLen = in.readShort();
                if(keyBytesE != null) {
                    in.skipBytes(idLen);
                    short keyLen = in.readShort();
                    in.skipBytes(keyLen);
                }
                else{
                    byte[] pidBytes = new byte[idLen];
                    in.readFully(pidBytes);
                    short keyLen = in.readShort();
                    if(Arrays.equals(pidBytes, userPidBytes)){
                        keyBytesE = new byte[keyLen];
                        in.readFully(keyBytesE);
                    }
                    else {
                        in.skipBytes(keyLen);
                    }
                }
            }

            if(keyBytesE == null){
                throw new CryptoException("No key in message for this user!");
            }

            // Decrypt AES key
			Cipher keyCipher = Cipher.getInstance("RSA");
            keyCipher.init(Cipher.DECRYPT_MODE, mIdent.userPrivateKey());
            CipherInputStream is = new CipherInputStream(
                new ByteArrayInputStream(keyBytesE), keyCipher);
            byte[] aesKey = new byte[AES_Key_Size/8];
            is.read(aesKey);
            is.close();

            short ivLen = in.readShort();
            byte[] ivBytes = new byte[ivLen];
            in.readFully(ivBytes);

            int dataLen = in.readInt();
            // Note the rest of the bytes are the body.
            // We'll just pipe them into the decrypt stream...

            // Use AES key to decrypt the body
            SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
            IvParameterSpec ivspec = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aeskeySpec, ivspec);
            is = new CipherInputStream(in, cipher);
            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            Util.copy(is, plainOut);
            is.close();

			byte[] plainBytes = plainOut.toByteArray();
            String plainText = new String(plainBytes, "UTF8");
			return plainText;

		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new CryptoException();
		}
	}

	public String prepareOutgoingMessage(String s, List<PublicKey> toPubKeys)
        throws CryptoException {
		try {
			byte[] plain = s.getBytes("UTF8");
            byte[] aesKey = makeAESKey();
            SecretKeySpec aesSpec = new SecretKeySpec(aesKey, "AES");

			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(mIdent.userPrivateKey(), new SecureRandom());

            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            SignatureOutputStream so = new SignatureOutputStream(bo, signature);
            ObjectOutputStream out = new ObjectOutputStream(so);
            
			byte[] userPidBytes = mIdent.userPersonId().getBytes("UTF8");
            out.writeShort(userPidBytes.length);
            out.write(userPidBytes);

            out.writeShort(toPubKeys.size());

            // Encrypt the AES key with each key in toPubKeys
            for(PublicKey pubk : toPubKeys){
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, pubk);
                ByteArrayOutputStream ks = new ByteArrayOutputStream();
                CipherOutputStream os = new CipherOutputStream(ks, cipher);
                os.write(aesKey);
                os.close();
                byte[] aesKeyCipherBytes = ks.toByteArray();
                
                String pid = mIdent.personIdForPublicKey(pubk);
                byte[] toPersonIdBytes = pid.getBytes("UTF8");
                out.writeShort(toPersonIdBytes.length);
                out.write(toPersonIdBytes);

                out.writeShort(aesKeyCipherBytes.length);
                out.write(aesKeyCipherBytes);
            }

            // Generate Initialization Vector for AES CBC mode
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            out.writeShort(iv.length);
            out.write(iv);

            // Use AES key to encrypt the body
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesSpec, ivspec);
            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            CipherOutputStream aesOut = new CipherOutputStream(cipherOut, aesCipher);
            aesOut.write(plain);
            aesOut.close();
			byte[] cipherData = cipherOut.toByteArray();
            out.writeInt(cipherData.length);
            out.write(cipherData);
            out.close();

			byte[] sigBytes = signature.sign();
            byte[] allBytes = bo.toByteArray();

			return Base64.encodeToString(sigBytes, false) + "," + Base64.encodeToString(allBytes, false);

		} catch (Exception e) {
			e.printStackTrace(System.err);
			throw new CryptoException();
		}
	}


    /**
     * Creates a new AES key
     */
	private byte[] makeAESKey() throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
	    kgen.init(AES_Key_Size);
	    SecretKey key = kgen.generateKey();
	    return key.getEncoded();
	}
}
