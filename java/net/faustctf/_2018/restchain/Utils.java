package net.faustctf._2018.restchain;

import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

class Utils {
	private Utils() {
	}

	static String encodeQueryString(Map<String, String> params) {
		if (params == null || params.size() == 0) {
			return "";
		}

		StringBuilder qs = new StringBuilder();
		for (Map.Entry<String, String> entry : params.entrySet()) {
			try {
				qs.append(qs.length() == 0 ? '?' : '&');
				qs.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
				qs.append('=');
				qs.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				throw new UncheckedIOException(e);
			}
		}
		return qs.toString();
	}
}
