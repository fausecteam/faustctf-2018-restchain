package net.faustctf._2018.restchain;

import java.io.Serializable;
import java.net.HttpURLConnection;
import java.util.Map;

/**
 * Class representation of RESTchain block access tokens.
 * <p>
 * To make use of an access token, just pass it to {@link RESTchainClient#getBlock(String, AccessToken)}. To generate a
 * new access token, check out the methods of {@link AccessTokenFactory}, an instance of which can be obtained from
 * {@link RESTchainClient#getAccessTokenFactory()}.
 */
public class AccessToken implements Serializable {
	private Map<String, String> addHeaders;

	AccessToken(Map<String, String> addHeaders) {
		this.addHeaders = addHeaders;
	}

	void apply(HttpURLConnection connection) {
		for (Map.Entry<String, String> entry : addHeaders.entrySet()) {
			connection.addRequestProperty(entry.getKey(), entry.getValue());
		}
	}
}
