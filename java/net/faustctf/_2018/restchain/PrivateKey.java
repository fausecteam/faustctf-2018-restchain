package net.faustctf._2018.restchain;

import java.io.Serializable;

/**
 * Representation of a private key
 */
public class PrivateKey implements Serializable {
	private String privateKey;
	private PublicKey publicKey;

	PrivateKey(String privateKey, PublicKey publicKey) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}

	@Override
	public String toString() {
		return "PrivateKey{" +
				"privateKey='" + privateKey + '\'' +
				", publicKey=" + publicKey +
				'}';
	}

	/**
	 * Get the corresponding public key
	 *
	 * @return Public key
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Get the string representation of the private key as used by the API.
	 *
	 * @return Private key String
	 */
	String getPrivateKey() {
		return privateKey;
	}
}
