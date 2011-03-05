package edu.stanford.mobisocial.bumblebee;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;

public class Main {

	private static KeyPair loadKeyPair(String file){
		try{
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			// get user password and file input stream
			char[] password = {};
			FileInputStream fis = new FileInputStream(file);
			ks.load(fis, password);
			fis.close();
			try {
				String alias = "privateKeyAlias";
				// Get private key
				Key key = ks.getKey("privateKeyAlias", password);
				if (key instanceof PrivateKey) {
					// Get certificate of public key
					Certificate cert = ks.getCertificate(alias);
					// Get public key
					PublicKey publicKey = cert.getPublicKey();
					// Return a key pair
					return new KeyPair(publicKey, (PrivateKey)key);
				}
			} catch (UnrecoverableKeyException e) {
			} catch (NoSuchAlgorithmException e) {
			} catch (KeyStoreException e) {
			}
			return null;
		}
		catch(Exception e){
			return null;
		}
		
	}

	public static void main( String[] args ){

		if(args.length < 1){
			System.out.println("Usage: PROGRAM mykeyfile otherkeyfile");
			System.exit(0);
		}

		final KeyPair mykeys = loadKeyPair(args[0]);
		final KeyPair otherkeys = loadKeyPair(args[1]);

		MessengerService m = new XMPPMessengerService(
			new StandardIdentity(mykeys.getPublic(), mykeys.getPrivate()));
		m.addStateListener(new StateListener(){
				public void onReady(){
					System.out.println("READY!");
				}
				public void onNotReady(){}
			});
		m.addMessageListener(new MessageListener(){
				public void onMessage(IncomingMessage m){
					System.out.println("Got message! " + m.toString());
				}
			});

		m.init();

		try{
			String curLine = ""; // Line read from standard in
			InputStreamReader converter = new InputStreamReader(System.in);
			BufferedReader in = new BufferedReader(converter);
			while (!(curLine.equals("q"))){
				curLine = in.readLine();
				final String line = curLine;
				if (!(curLine.equals("q"))){
					m.sendMessage(new OutgoingMessage(){
							public PublicKey toPublicKey(){ return otherkeys.getPublic(); }
							public String contents(){ return line; }
						});
					System.out.println("You typed: " + curLine);
				}
			}
		}
		catch(IOException e){
			e.printStackTrace(System.err);
		}
	}


}
