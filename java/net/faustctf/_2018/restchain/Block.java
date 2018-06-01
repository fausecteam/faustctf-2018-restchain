package net.faustctf._2018.restchain;

import java.io.IOException;
import java.io.Serializable;
import java.net.HttpURLConnection;

public class Block implements Serializable {
	private String id;
	private String previousId;
	private SignedData signedData;
	private String signedDataHash;
	private PublicKey signer;
	private Signature signature;

	Block(String id, String previousId, SignedData signedData, String signedDataHash, PublicKey signer, Signature signature) {
		this.id = id;
		this.previousId = previousId;
		this.signedData = signedData;
		this.signedDataHash = signedDataHash;
		this.signer = signer;
		this.signature = signature;
	}

	Block(String id, HttpURLConnection connection, byte[] body) throws IOException {
		this.id = id;
		this.previousId = connection.getHeaderField("X-Restchain-Previous");
		this.signedDataHash = connection.getHeaderField("X-Restchain-Payload-Hash");
		this.signer = new PublicKey(connection.getHeaderField("X-Restchain-Signer"));
		this.signature = new Signature(connection.getHeaderField("X-Restchain-Signature"));
		if (connection.getResponseCode() == 200) {
			this.signedData = new SignedData(connection, body);
		}
	}

	public String getId() {
		return id;
	}

	void setId(String id) {
		this.id = id;
	}

	public String getPreviousId() {
		return previousId;
	}

	void setPreviousId(String previousId) {
		this.previousId = previousId;
	}

	public SignedData getSignedData() {
		return signedData;
	}

	void setSignedData(SignedData signedData) {
		this.signedData = signedData;
	}

	public String getSignedDataHash() {
		return signedDataHash;
	}

	void setSignedDataHash(String signedDataHash) {
		this.signedDataHash = signedDataHash;
	}

	public PublicKey getSigner() {
		return signer;
	}

	void setSigner(PublicKey signer) {
		this.signer = signer;
	}

	public Signature getSignature() {
		return signature;
	}

	void setSignature(Signature signature) {
		this.signature = signature;
	}


	@Override
	public String toString() {
		return "Block{" +
				"id='" + id + '\'' +
				", previousId='" + previousId + '\'' +
				", signedData=" + signedData +
				", signedDataHash='" + signedDataHash + '\'' +
				", signer=" + signer +
				", signature=" + signature +
				'}';
	}

	void setHeaders(HttpURLConnection connection) {
		signedData.setHeaders(connection);
		connection.setRequestProperty("X-Restchain-Previous", previousId);
		connection.setRequestProperty("X-Restchain-Signer", signer.getPublicKey());
		connection.setRequestProperty("X-Restchain-Signature", signature.getSignatureString());
	}
}
