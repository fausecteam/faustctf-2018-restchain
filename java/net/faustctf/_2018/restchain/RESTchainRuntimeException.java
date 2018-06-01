package net.faustctf._2018.restchain;

public class RESTchainRuntimeException extends RuntimeException {
	public RESTchainRuntimeException(String message, Exception e) {
		super(message, e);
	}
}
