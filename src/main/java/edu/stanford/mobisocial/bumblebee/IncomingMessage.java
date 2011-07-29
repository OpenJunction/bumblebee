package edu.stanford.mobisocial.bumblebee;

public interface IncomingMessage {
	public String from();

	public String contents();

	public byte[] encoded();
}
