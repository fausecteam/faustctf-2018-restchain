package net.faustctf._2018.restchain;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.util.*;

public class SignedData implements Serializable {
	private Map<String, List<String>> headers;
	private String contentType;
	private byte[] body;

	/**
	 * @param headers     Additional metadata stored alongside the body
	 * @param contentType MIME type of body
	 * @param body        Actual data
	 */
	public SignedData(Map<String, List<String>> headers, String contentType, byte[] body) {
		this.headers = headers;
		this.contentType = contentType;
		this.body = body;
	}

	/**
	 * Initialize a SignedData object with no headers
	 *
	 * @param contentType MIME type of body
	 * @param body        Actual data
	 */
	public SignedData(String contentType, byte[] body) {
		this.headers = new HashMap<>();
		this.contentType = contentType;
		this.body = body;
	}

	/**
	 * Create a new signed data object with a string as body. The contents of the string will be encoded as UTF-8. If
	 * you want another encoding, please encode it yourself and use the constructur taking a byte array.
	 *
	 * @param contentType MIME type of body
	 * @param body        Data body as a string to be UTF-8 encoded
	 */
	public SignedData(String contentType, String body) {
		this(contentType, (byte[]) null);
		setBody(body);
	}

	SignedData(HttpURLConnection connection, byte[] body) {
		this.contentType = connection.getContentType();
		this.body = body;
		this.headers = new HashMap<>();
		for (Map.Entry<String, List<String>> entry : connection.getHeaderFields().entrySet()) {
			String name = entry.getKey();
			if (name == null) {
				// Somehow null -> "HTTP/1.1 200 OK" is a header for java...
				continue;
			}
			if (name.startsWith(Constants.BLOCK_HEADER_PREFIX)) {
				name = name.substring(Constants.BLOCK_HEADER_PREFIX.length());
				for (String value : entry.getValue()) {
					addHeader(name, value);
				}
			}
		}
	}

	public Map<String, List<String>> getHeaders() {
		return headers;
	}

	public void setHeaders(Map<String, List<String>> headers) {
		this.headers = headers;
	}

	public String getContentType() {
		return contentType;
	}

	public void setContentType(String contentType) {
		this.contentType = contentType;
	}

	public byte[] getBody() {
		return body;
	}

	public void setBody(byte[] body) {
		this.body = body;
	}

	public void setBody(String body) {
		try {
			this.body = body.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("For some reason this JVM does not know UTF-8...", e);
		}
	}

	/**
	 * Return the value of a given header. If multiple headers with the name exist, one of the values is returned (use
	 * {@link SignedData#getHeaderAll(String)} if you are expecting multiple headers with the same name to exist). If no
	 * header with this name exists, null is returned.
	 *
	 * @param name Header name
	 * @return Header value
	 */
	public String getHeader(String name) {
		List<String> values = headers.get(name);
		if (values == null || values.size() == 0) {
			return null;
		} else {
			return values.get(0);
		}
	}

	/**
	 * When creating a new {@link Block}, use this to protect it with an {@link Acl}.
	 *
	 * @param acl ACL obtained from {@link AclFactory}
	 */
	public void setAcl(Acl acl) {
		setHeader("Acl", acl.getAclString());
	}

	public Acl getAcl() {
		String aclString = getHeader("Acl");
		if (aclString != null) {
			return new Acl(aclString);
		} else {
			return null;
		}
	}

	/**
	 * Returns a list of the values of all headers with a given name
	 *
	 * @param name Header name
	 * @return List of values, never null
	 */
	public List<String> getHeaderAll(String name) {
		List<String> values = headers.get(name);
		if (values != null) {
			return values;
		} else {
			return new ArrayList<>();
		}
	}

	/**
	 * Add a header, if a header with the same name already exists, an additional header is created
	 *
	 * @param name Header name
	 * @param value Header value
	 */
	public void addHeader(String name, String value) {
		headers.putIfAbsent(name, new ArrayList<>());
		List<String> values = headers.get(name);
		values.add(value);
	}

	/**
	 * Set a header, replacing all existing headers with the same name
	 *
	 * @param name Header name
	 * @param value Header value
	 */
	public void setHeader(String name, String value) {
		headers.put(name, Arrays.asList(value));
	}

	/**
	 * If a headers with the given name exist, remove all of them
	 *
	 * @param name Header name
	 */
	public void deleteHeader(String name) {
		headers.remove(name);
	}

	void setHeaders(HttpURLConnection connection) {
		for (Map.Entry<String, List<String>> header : headers.entrySet()) {
			String prefixedHeader = Constants.BLOCK_HEADER_PREFIX + header.getKey();
			for (String value : header.getValue()) {
				connection.addRequestProperty(prefixedHeader, value);
			}
		}
		connection.setRequestProperty("Content-Type", this.contentType);
	}

	@Override
	public String toString() {
		String bodyString;
		if (contentType.startsWith("text/")) {
			bodyString = "'" + new String(body) + "'";
		} else {
			bodyString = Arrays.toString(body);
		}
		return "SignedData{" +
				"headers=" + headers +
				", contentType='" + contentType + '\'' +
				", body=" + bodyString +
				'}';
	}
}
