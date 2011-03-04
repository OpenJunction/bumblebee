package edu.stanford.mobisocial.bumblebee;

public class StandardIdentity implements Identity{

	private String pkey;

    public StandardIdentity(String pkey){
		this.pkey = pkey;
	}

    public String publicKey(){
		return pkey;
	}

    public String encrypt(String s){
		return s;
	}
	
}