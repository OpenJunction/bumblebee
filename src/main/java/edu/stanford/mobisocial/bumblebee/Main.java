package edu.stanford.mobisocial.bumblebee;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.*;
import java.util.*;

public class Main {


    public static PrivateKey loadPrivateKey(String filename){
        try{
            File f = new File(filename);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int)f.length()];
            dis.readFully(keyBytes);
            dis.close();

            PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
        catch(Exception e){
            e.printStackTrace(System.err);
            System.exit(0);
            return null;
        }
    }

    public static PublicKey loadPublicKey(String filename){
        try{    
            File f = new File(filename);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int)f.length()];
            dis.readFully(keyBytes);
            dis.close();

            X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
        catch(Exception e){
            e.printStackTrace(System.err);
            System.exit(0);
            return null;
        }
    }


	public static void main(String[] args) {
        final String myKeyPrefix = args[0];
        final String otherKeyPrefix = args[1];
        final PublicKey myPubKey = loadPublicKey("etc/" + myKeyPrefix + "_public_key.der");
        final PrivateKey myPrivKey = loadPrivateKey("etc/" + myKeyPrefix + "_private_key.der");
        final PublicKey otherPubKey = loadPublicKey("etc/" + otherKeyPrefix + "_public_key.der");

		MessengerService m = new XMPPMessengerService(new StandardIdentity(
                                                          myPubKey, myPrivKey));
		m.addStateListener(new StateListener() {
                public void onReady() {
                    System.out.println("READY!");
                }

                public void onNotReady() {
                }
            });
		m.addMessageListener(new MessageListener() {
                public void onMessage(IncomingMessage m) {
                    System.out.println("Got message! " + m.toString());
                }
            });

		m.init();

		try {
			String curLine = ""; // Line read from standard in
			InputStreamReader converter = new InputStreamReader(System.in);
			BufferedReader in = new BufferedReader(converter);

			while (!(curLine.equals("q"))) {
				curLine = in.readLine();

				final String line = curLine;

				if (!(curLine.equals("q"))) {
					m.sendMessage(new OutgoingMessage() {
                            public PublicKey toPublicKey() {
                                return otherPubKey;
                            }

                            public String contents() {
                                return line;
                            }
                        });
					System.out.println("You typed: " + curLine);
				}
			}
		} catch (IOException e) {
			e.printStackTrace(System.err);
		}
	}
}
