package edu.stanford.mobisocial.bumblebee;

public class CryptoException extends Exception {

	public CryptoException(String msg) {
		super(msg);
	}

	public CryptoException() {
		this("");
	}
}
