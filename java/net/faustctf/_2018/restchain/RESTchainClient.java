package net.faustctf._2018.restchain;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;

/**
 * Client for the powerful RESTchain
 */
public class RESTchainClient {
	private final String apiUrl;
	private final AclFactory aclFactory;
	private final AccessTokenFactory accessTokenFactory;
	private final int connectTimeout = 10 * 1000;
	private final int readTimeout = 10 * 1000;

	/**
	 * Initialize a client for some API URL like "http://localhost:6060/api"
	 *
	 * @param apiUrl API URL
	 */
	public RESTchainClient(String apiUrl) {
		this.apiUrl = apiUrl;
		this.aclFactory = new AclFactory(this);
		this.accessTokenFactory = new AccessTokenFactory(this);
	}

	private URL makeUrl(String... params) throws MalformedURLException {
		return new URL(apiUrl + "/" + String.join("/", params));
	}

	private HttpURLConnection makeConnection(URL url) throws IOException {
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setConnectTimeout(connectTimeout);
		connection.setReadTimeout(readTimeout);
		return connection;
	}

	private HttpURLConnection makeConnection(String... params) throws IOException {
		return makeConnection(makeUrl(params));
	}

	private BufferedReader makeReader(HttpURLConnection c) throws IOException {
		return new BufferedReader(new InputStreamReader(c.getInputStream()));
	}

	private BufferedInputStream makeInputStream(HttpURLConnection c) throws IOException {
		try {
			return new BufferedInputStream(c.getInputStream());
		} catch (IOError e) {
			return new BufferedInputStream(c.getErrorStream());
		}
	}

	private BufferedOutputStream makeOutputStream(HttpURLConnection c) throws IOException {
		return new BufferedOutputStream(c.getOutputStream());
	}

	private byte[] readBody(BufferedInputStream reader) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int b;
		while ((b = reader.read()) != -1) {
			buffer.write(b);
		}
		return buffer.toByteArray();
	}

	private String readBodyString(BufferedInputStream reader, String encoding) throws IOException {
		return new String(readBody(reader), encoding);
	}

	private String readBodyString(BufferedInputStream reader) throws IOException {
		return readBodyString(reader, "UTF-8");
	}

	/**
	 * Generate a new key pair using the API
	 *
	 * @return Private key generated
	 * @throws IOException Network error
	 */
	public PrivateKey generatePrivateKey() throws IOException {
		HttpURLConnection connection = makeConnection("crypto", "privatekey");
		connection.setRequestMethod("GET");
		connection.connect();
		String publicKeyString = connection.getHeaderField("X-Restchain-Public-Key");
		String privateKeyString = connection.getHeaderField("X-Restchain-Private-Key");
		PublicKey publicKey = new PublicKey(publicKeyString);
		PrivateKey privateKey = new PrivateKey(privateKeyString, publicKey);
		return privateKey;
	}

	/**
	 * Sign some data using the API
	 *
	 * @param privateKey Private key to sign with
	 * @param data Data to be signed
	 * @return Signature for data using privateKey
	 * @throws IOException Network error
	 */
	public Signature sign(PrivateKey privateKey, SignedData data) throws IOException {
		HttpURLConnection connection = makeConnection("crypto", "sign");
		connection.setRequestMethod("POST");
		connection.setDoOutput(true);
		data.setHeaders(connection);
		connection.setRequestProperty("X-Restchain-Private-Key", privateKey.getPrivateKey());
		connection.connect();
		connection.getOutputStream().write(data.getBody());
		String signatureString = connection.getHeaderField("X-Restchain-Signature");
		return new Signature(signatureString);
	}

	/**
	 * Verify a signature
	 *
	 * @param publicKey Public key to verify the signature against
	 * @param data Data object to verify the signature against
	 * @param signature Singature to be verified
	 * @return Boolean indicating if the signature is valid
	 * @throws IOException Network error
	 * @throws RESTchainException RESTchain internal error
	 */
	public boolean verify(PublicKey publicKey, SignedData data, Signature signature) throws IOException, RESTchainException {
		HttpURLConnection connection = makeConnection("crypto", "verify");
		connection.setRequestMethod("POST");
		connection.setDoOutput(true);
		data.setHeaders(connection);
		connection.setRequestProperty("X-Restchain-Public-Key", publicKey.getPublicKey());
		connection.setRequestProperty("X-Restchain-Signature", signature.getSignatureString());
		connection.connect();
		connection.getOutputStream().write(data.getBody());
		try {
			int responseCode = connection.getResponseCode();
			String responseBody = readBodyString(makeInputStream(connection)).trim();
			if (responseCode == 200 && "OK".equals(responseBody)) {
				return true;
			} else if (responseCode == 418 && "FAIL".equals(responseBody)) {
				return false;
			} else {
				throw new RESTchainException(responseCode, responseBody);
			}
		} catch (IOException e) {
			// Somehow java is super weird and throws an exception in .getResponseCode() if it's not an OK code?!
			if (e.getMessage().startsWith("Server returned HTTP response code: 418 for URL: ")) {
				return false;
			} else {
				throw e;
			}
		}
	}

	/**
	 * Access a restricted block using the given {@link AccessToken}
	 *
	 * @param blockId ID of the block to be accessed
	 * @param accessToken Access token used to access the block
	 * @return The requested block
	 * @throws IOException Network error
	 * @throws RESTchainBlockPermissionDenied Block access denied by ACL
	 * @throws RESTchainBlockNotFound Block not found
	 * @throws RESTchainException RESTchain internal error
	 */
	public Block getBlock(String blockId, AccessToken accessToken) throws IOException, RESTchainException {
		HttpURLConnection connection = makeConnection("block", blockId);
		if (accessToken != null) {
			accessToken.apply(connection);
		}
		connection.connect();
		if (connection.getResponseCode() == 200) {
			byte[] body = readBody(makeInputStream(connection));
			return new Block(blockId, connection, body);
		} else if (connection.getResponseCode() == 403) {
			Block blockStub = new Block(blockId, connection, null);
			throw new RESTchainBlockPermissionDenied(connection.getResponseCode(), connection.getResponseMessage(), blockStub);
		} else if (connection.getResponseCode() == 404) {
			throw new RESTchainBlockNotFound(connection.getResponseCode(), connection.getResponseMessage());
		} else {
			throw new RESTchainException(connection.getResponseCode(), connection.getResponseMessage());
		}
	}

	/**
	 * Access a publicly accessible block
	 *
	 * @param blockId ID of the block to be accessed
	 * @return The requested block
	 * @throws IOException Network error
	 * @throws RESTchainBlockPermissionDenied Block access denied by ACL
	 * @throws RESTchainBlockNotFound Block not found
	 * @throws RESTchainException RESTchain internal error
	 */
	public Block getBlock(String blockId) throws IOException, RESTchainException {
		return getBlock(blockId, null);
	}

	/**
	 * @return Get the RESTchain genesis block
	 * @throws IOException Network error
	 */
	public Block getGenesisBlock() throws IOException {
		try {
			return getBlock(Constants.GENESIS_BLOCK_ID);
		} catch (RESTchainException e) {
			throw new RESTchainRuntimeException("could not get genesis block", e);
		}
	}

	/**
	 * Put a new block on the blockchain
	 *
	 * @param previousBlockId ID of the preceding block
	 * @param data Data used for the new block
	 * @param privateKey Private key used to sign the new block
	 * @return The newly created block
	 * @throws IOException Network error
	 * @throws RESTchainException RESTchain internal error
	 */
	public Block putBlock(String previousBlockId, SignedData data, PrivateKey privateKey) throws IOException, RESTchainException {
		Signature signature = sign(privateKey, data);
		HttpURLConnection connection = makeConnection("block");
		connection.setRequestMethod("PUT");
		connection.setDoOutput(true);
		Block block = new Block(null, previousBlockId, data, null, privateKey.getPublicKey(), signature);
		block.setHeaders(connection);
		connection.connect();
		connection.getOutputStream().write(block.getSignedData().getBody());
		int responseCode = connection.getResponseCode();
		if (responseCode == 200 || responseCode == 303) {
			block.setId(connection.getHeaderField("X-Restchain-Id"));
			block.setSignedDataHash(connection.getHeaderField("X-Restchain-Payload-Hash"));
			return block;
		} else {
			throw new RESTchainException(responseCode, readBodyString(makeInputStream(connection)));
		}
	}

	/**
	 * Put a new block on the blockchain
	 *
	 * @param previousBlock The preceding block
	 * @param data Data used for the new block
	 * @param privateKey Private key used to sign the new block
	 * @return The newly created block
	 * @throws IOException Network error
	 * @throws RESTchainException RESTchain internal error
	 */
	public Block putBlock(Block previousBlock, SignedData data, PrivateKey privateKey) throws IOException, RESTchainException {
		return putBlock(previousBlock.getId(), data, privateKey);
	}

	Acl getAclRaw(String aclName, Map<String, String> params) throws IOException {
		HttpURLConnection connection = makeConnection("acl", aclName + Utils.encodeQueryString(params));
		connection.connect();
		String aclString = readBodyString(makeInputStream(connection)).trim();
		return new Acl(aclString);
	}

	/**
	 * Get a factory to create {@link Acl} objects
	 *
	 * @return The ACL factory
	 */
	public AclFactory getAclFactory() {
		return aclFactory;
	}

	/**
	 * Get a factory to create {@link AccessToken} objects
	 *
	 * @return The access token factory
	 */
	public AccessTokenFactory getAccessTokenFactory() {
		return accessTokenFactory;
	}
}
