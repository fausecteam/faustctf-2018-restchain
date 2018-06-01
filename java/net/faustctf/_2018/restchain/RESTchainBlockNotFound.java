package net.faustctf._2018.restchain;

public class RESTchainBlockNotFound extends RESTchainException {
	public RESTchainBlockNotFound(int statusCode, String message) {
		super(statusCode, message);
	}
}
