package net.faustctf._2018.restchain;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class AclFactory {
	private final RESTchainClient client;

	AclFactory(RESTchainClient client) {
		this.client = client;
	}

	public Acl alwaysAllow() throws IOException {
		return client.getAclRaw("always-allow", null);
	}

	public Acl alwaysDeny() throws IOException {
		return client.getAclRaw("always-deny", null);
	}

	public Acl requireSecret(String secret) throws IOException {
		Map<String, String> params = new HashMap<>();
		params.put("secret", secret);
		return client.getAclRaw("require-secret", params);
	}

	public Acl requireSignature(Map<String, PublicKey> allowedKeys) throws IOException {
		Map<String, String> params = new HashMap<>();
		for (Map.Entry<String, PublicKey> entry : allowedKeys.entrySet()) {
			String keyId = entry.getKey();
			String keyParam = "key[" + keyId + "]";
			params.put(keyParam, entry.getValue().getPublicKey());
		}
		return client.getAclRaw("require-signature", params);
	}
}
