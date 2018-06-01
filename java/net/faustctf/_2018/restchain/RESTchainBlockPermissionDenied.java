package net.faustctf._2018.restchain;

public class RESTchainBlockPermissionDenied extends RESTchainException {
	private Block blockStub;

	RESTchainBlockPermissionDenied(int statusCode, String message, Block blockStub) {
		super(statusCode, message);
		this.blockStub = blockStub;
	}

	RESTchainBlockPermissionDenied(int statusCode, String message, Block blockStub, Exception e) {
		super(statusCode, message, e);
		this.blockStub = blockStub;
	}

	public Block getBlockStub() {
		return blockStub;
	}
}
