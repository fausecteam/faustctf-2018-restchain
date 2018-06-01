package net.faustctf._2018.restchain;

import java.util.HashMap;
import java.util.Map;

class SelfTest {
	public static void main(String[] args) throws Exception {
		String apiUrl = "http://localhost:6060/api";
		if (args.length >= 1) {
			apiUrl = args[0];
		}
		RESTchainClient client = new RESTchainClient(apiUrl);

		// key generation
		PrivateKey privateKey = client.generatePrivateKey();
		System.out.println("Private Key: " + privateKey);
		PublicKey publicKey = privateKey.getPublicKey();
		System.out.println("Public Key: " + publicKey);

		// sign/verify operations
		SignedData data = new SignedData("text/plain", "Hello World!");
		data.addHeader("X-Test", "foo");
		data.addHeader("X-Test", "bar");
		Signature signature = client.sign(privateKey, data);
		System.out.println("Signature: " + signature);

		System.out.println("Verify (ok): " + client.verify(publicKey, data, signature));
		data.addHeader("X-Data-Tampered-With", "yes");
		System.out.println("Verify (message tampered with): " + client.verify(publicKey, data, signature));
		data.deleteHeader("X-Data-Tampered-With");

		// block operations
		Block genesisBlock = client.getGenesisBlock();
		System.out.println("Genesis Block: " + genesisBlock);

		Block newBlock = genesisBlock;
		for (int i = 0; i < 3; i++) {
			newBlock = client.putBlock(newBlock, data, privateKey);
			System.out.println("New block: " + newBlock);
		}

		// acl generation
		Acl alwaysAllowAcl = client.getAclFactory().alwaysAllow();
		System.out.println("Acl always-allow: " + alwaysAllowAcl);

		Acl alwaysDenyAcl = client.getAclFactory().alwaysDeny();
		System.out.println("Acl always-deny: " + alwaysDenyAcl);

		String secret = "FAUST rocks!";
		Acl requireSecretAcl = client.getAclFactory().requireSecret(secret);
		System.out.println("Acl require-secret: " + requireSecretAcl);

		String keyId = "Test";
		Map<String, PublicKey> allowedKeys = new HashMap<>();
		allowedKeys.put(keyId, publicKey);
		Acl requireSignatureAcl = client.getAclFactory().requireSignature(allowedKeys);
		System.out.println("Acl require-signature: " + requireSignatureAcl);

		// acl tests
		data.setAcl(alwaysAllowAcl);
		newBlock = client.putBlock(newBlock, data, privateKey);
		newBlock = client.getBlock(newBlock.getId());
		System.out.println("get always-allow block: " + newBlock);

		data.setAcl(alwaysDenyAcl);
		newBlock = client.putBlock(newBlock, data, privateKey);
		try {
			newBlock = client.getBlock(newBlock.getId());
			throw new RuntimeException("get always-deny block: " + newBlock);
		} catch (RESTchainBlockPermissionDenied e) {
			System.out.println("get always-deny block: " + e);
			System.out.println("block stub: " + e.getBlockStub());
		}

		data.setAcl(requireSecretAcl);
		newBlock = client.putBlock(newBlock, data, privateKey);
		try {
			newBlock = client.getBlock(newBlock.getId());
			throw new RuntimeException("get require-secret block (unauthorized): " + newBlock);
		} catch (RESTchainBlockPermissionDenied e) {
			System.out.println("get require-secret block (unauthorized): " + e);
			System.out.println("block stub: " + e.getBlockStub());
		}
		AccessToken requireSecretAccessToken = client.getAccessTokenFactory().requireSecret(secret);
		newBlock = client.getBlock(newBlock.getId(), requireSecretAccessToken);
		System.out.println("get require-secret block (authorized): " + newBlock);

		data.setAcl(requireSignatureAcl);
		newBlock = client.putBlock(newBlock, data, privateKey);
		try {
			newBlock = client.getBlock(newBlock.getId());
			throw new RuntimeException("get require-signature block (unauthorized): " + newBlock);
		} catch (RESTchainBlockPermissionDenied e) {
			System.out.println("get require-signature block (unauthorized): " + e);
			System.out.println("block stub: " + e.getBlockStub());
		}
		AccessToken requireSignatureAccessToken = client.getAccessTokenFactory().requireSignature(keyId, privateKey);
		newBlock = client.getBlock(newBlock.getId(), requireSignatureAccessToken);
		System.out.println("get require-signature block (authorized): " + newBlock);
	}
}
