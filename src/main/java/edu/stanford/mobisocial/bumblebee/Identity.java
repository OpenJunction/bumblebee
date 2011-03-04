package edu.stanford.mobisocial.bumblebee;

public interface Identity {
	public String publicKey();
	public String encrypt(String s);
}