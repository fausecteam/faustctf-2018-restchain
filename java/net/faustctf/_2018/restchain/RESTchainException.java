package net.faustctf._2018.restchain;

public class RESTchainException extends Exception {
	public RESTchainException(int statusCode, String message) {
		super("[" + statusCode + "] " + message);
	}

	public RESTchainException(int statusCode, String message, Exception e) {
		super("[" + statusCode + "] " + message, e);
	}
}
