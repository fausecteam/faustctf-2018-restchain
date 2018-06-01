package net.faustctf._2018.restchain;

import java.io.Serializable;

/**
 * Class wrapping the internal representation of s RESTchain public key.
 */
public class PublicKey implements Serializable {
	private String publicKey;

	/**
	 * Construct a public key object from either a key received from the API (this is transparently done in {@link
	 * RESTchainClient} already) or from local storage.
	 *
	 * @param publicKey public key as received from the RESTchain API
	 */
	PublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	/**
	 * Returns a human-readable representation of the public key. Do not rely on the format of the key as it can change
	 * at any time without further notice.
	 *
	 * @return String representation of the public key
	 */
	@Override
	public String toString() {
		return "PublicKey(" + publicKey + ")";
	}

	/**
	 * Get a string representation of the public key that can either be sent to the RESTchain API or stored somewhere
	 * for later use.
	 *
	 * @return String representation of the public key as understood by the RESTchain API
	 */
	public String getPublicKey() {
		return publicKey;
	}
}
