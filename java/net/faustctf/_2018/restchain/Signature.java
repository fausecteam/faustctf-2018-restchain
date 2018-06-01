package net.faustctf._2018.restchain;

import java.io.Serializable;

/**
 * Representation of a signature
 */
public class Signature implements Serializable {
	private String signature;

	Signature(String signature) {
		this.signature = signature;
	}

	@Override
	public String toString() {
		return "Signature{" +
				"signature='" + signature + '\'' +
				'}';
	}

	/**
	 * Get the string representation of the signature as used by the RESTchain API
	 *
	 * @return String representation
	 */
	public String getSignatureString() {
		return signature;
	}
}
