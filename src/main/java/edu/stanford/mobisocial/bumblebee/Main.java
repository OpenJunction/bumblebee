package edu.stanford.mobisocial.bumblebee;

public class Main {

    public static void main( String[] args ){
		MessengerService m = new XMPPMessengerService(new StandardIdentity("lskjdf"));
		m.addStateListener(new StateListener(){
				public void onReady(){
					System.out.println("READY!");
				}
				public void onNotReady(){}
			});
		m.addStateListener(new MessageListener(){
				public void onMessage(IncomingMessage m){
					System.out.println("READY!");
				}
			});
		m.init();
	}

}
