package edu.stanford.mobisocial.bumblebee;
import edu.stanford.mobisocial.bumblebee.util.*;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MessageFormat {

    public static final int AES_Key_Size = 128;
    public static final int SHORT_LEN = 2;
    private TransportIdentityProvider mIdent;

	public MessageFormat(TransportIdentityProvider ident) {
        mIdent = ident;
	}

	public String getMessagePersonId(byte[] s) {
        try{
        	RSAPublicKey k = getMessagePublicKey(s);
        	if(k == null)
        		return null;
        	return mIdent.personIdForPublicKey(k);
        }catch(Exception e){ e.printStackTrace(System.err); return null; }        
	}
	public RSAPublicKey getMessagePublicKey(byte[] s) {
        try{
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(s));
            short sigLen = in.readShort();
            in.skipBytes(sigLen);
            short fromPidLen = in.readShort();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] dest = new byte[fromPidLen];
            System.arraycopy(s, SHORT_LEN + sigLen + SHORT_LEN, dest, 0, fromPidLen);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(dest);
            return (RSAPublicKey)keyFactory.generatePublic(publicKeySpec);                
        }catch(Exception e){ e.printStackTrace(System.err); return null; }
	}

    private class ByteArrayInputStreamWithPos extends ByteArrayInputStream{
        public ByteArrayInputStreamWithPos(byte[] b){ super(b); }
        public int getPos(){ return pos; }
    }

	public String decodeIncomingMessage(byte[] s) throws CryptoException{
		try {
            ByteArrayInputStreamWithPos bi = new ByteArrayInputStreamWithPos(s);
            DataInputStream in = new DataInputStream(bi);

            short sigLen = in.readShort();
            byte[] sigIn = new byte[sigLen];
            in.readFully(sigIn);

            // Decrypt digest
            RSAPublicKey sender = getMessagePublicKey(s);
            Cipher sigcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            sigcipher.init(Cipher.DECRYPT_MODE, sender);
            byte[] sigBytes = sigcipher.doFinal(sigIn);

            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            sha1.update(s, SHORT_LEN + sigLen, s.length - (SHORT_LEN + sigLen));
            byte[] digest = sha1.digest();
            boolean status = Arrays.equals(digest, sigBytes);
            if(!status){throw new CryptoException("Failed to verify signature.");}

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
                    if(Util.bytesEqual(s, bi.getPos(), userPidBytes, 0, idLen)){
                        in.skipBytes(idLen);
                        short keyLen = in.readShort();
                        keyBytesE = new byte[keyLen];
                        in.readFully(keyBytesE);
                    }
                    else {
                        in.skipBytes(idLen);
                        short keyLen = in.readShort();
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
			throw new RuntimeException("crypto-failure", e);
		}
	}

	public byte[] encodeOutgoingMessage(String s, List<RSAPublicKey> toPubKeys)
        throws CryptoException {
		try {
			byte[] plain = s.getBytes("UTF8");
            byte[] aesKey = makeAESKey();
            SecretKeySpec aesSpec = new SecretKeySpec(aesKey, "AES");

            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bo);
            
			byte[] userPidBytes = mIdent.userPublicKey().getEncoded();
            out.writeShort(userPidBytes.length);
            out.write(userPidBytes);

            out.writeShort(toPubKeys.size());

            // Encrypt the AES key with each key in toPubKeys
            for(RSAPublicKey pubk : toPubKeys){
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
            bo.close();
            
            byte[] dataBytes = bo.toByteArray();

            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            byte[] digest = sha1.digest(dataBytes);
            // Encrypt digest
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, mIdent.userPrivateKey());
            byte[] sigBytes = cipher.doFinal(digest);

            ByteArrayOutputStream so = new ByteArrayOutputStream();
            DataOutputStream finalOut = new DataOutputStream(so);
            finalOut.writeShort(sigBytes.length);
            finalOut.write(sigBytes);
            finalOut.write(dataBytes);
            finalOut.close();
            return so.toByteArray();

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
