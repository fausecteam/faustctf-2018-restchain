package net.faustctf._2018.restchain;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Factory for generating {@link AccessToken} instances for accessing blocks restricted by ACLs
 * <p>
 * You can obtain an instance using {@link RESTchainClient#getAccessTokenFactory()} and then invoking any method of this
 * class to create an access token.
 */
public class AccessTokenFactory {
	private final RESTchainClient client;

	AccessTokenFactory(RESTchainClient client) {
		this.client = client;
	}

	/**
	 * Generate an access token for a block protected by the require-secret ACL ({@link AclFactory#requireSecret(String)})
	 *
	 * @param secret Shared secret used for block protection
	 * @return {@link AccessToken} allowing access to the block
	 */
	public AccessToken requireSecret(String secret) {
		Map<String, String> headers = new HashMap<>();
		headers.put("X-Restchain-Acl-Secret", secret);
		return new AccessToken(headers);
	}

	/**
	 * Generate an access token for a block protected by the require-signature ACL ({@link AclFactory#requireSignature(Map)})
	 *
	 * @param keyId Key ID as passed to {@link AclFactory#requireSignature(Map)}
	 * @param privateKey Private key corresponding to the public key stored under keyId, used to generate the signature
	 * @return {@link AccessToken} allowing access to the block
	 * @throws IOException Network error
	 */
	public AccessToken requireSignature(String keyId, PrivateKey privateKey) throws IOException {
		SignedData data = new SignedData("application/vnd.faust.faustctf-2018-restchain-access-signature", new byte[0]);
		Signature signature = client.sign(privateKey, data);
		Map<String, String> headers = new HashMap<>();
		headers.put("X-Restchain-Acl-Key-Id", keyId);
		headers.put("X-Restchain-Acl-Signature", signature.getSignatureString());
		return new AccessToken(headers);
	}
}
