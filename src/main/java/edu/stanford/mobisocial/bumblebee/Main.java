package edu.stanford.mobisocial.bumblebee;
import java.io.*;

public class Main {

    public static void main( String[] args ){
		if(args.length < 1){
			System.out.println("Usage: PROGRAM myPublicKey toPublicKey");
			System.exit(0);
		}
		final String pubKey = args[0];
		final String toPubKey = args[1];
		MessengerService m = new XMPPMessengerService(new StandardIdentity(pubKey));
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
							public String toPublicKey(){ return toPubKey; }
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
