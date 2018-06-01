/* RESTchain ACL Standard Library */
function allow() {
	process.exit(0);
}

function deny() {
	process.exit(13);
}

function allowIf(b) {
	if (b) allow();
}

function denyIf(b) {
	if (b) deny();
}

function allowIff(b) {
	allowIf(b);
	denyIf(!b);
}

function denyIff(b) {
	denyIf(b);
	allowIf(!b);
}

function __httpHeaderName(name) {
	return name.toUpperCase().replace(/[^A-Z0-9]/g, '_')
}

function blockHeader(name) {
	return process.env[__httpHeaderName(name)];
}

function httpHeader(name) {
	for (var n of [name, "X-Restchain-" + name]) {
		var v = process.env['HTTP_' + __httpHeaderName(n)];
		if (v !== undefined) return v
	}
}

function sha256(data) {
	return require('crypto').createHash('sha256').update(data).digest('hex');
}

function verifySignature(pubkey, signature, headers, contentType, body, callback_ok, callback_fail) {
	const http = require("http");
	const url = require('url');
	var apiUrl = process.env.__RESTCHAIN_LISTEN;
	if (apiUrl[0] == ':') {
		apiUrl = "localhost" + apiUrl;
	}
	apiUrl = "http://" + apiUrl + "/api";
	var options = url.parse(apiUrl);
	options.method = 'POST';
	options.headers = headers;
	options.path += '/crypto/verify';
	var req = http.request(options, function(res) {
		if (res.statusCode === 200) {
			callback_ok(true);
		} else if (res.statusCode === 418) {
			callback_fail(false);
		} else {
			console.log('Unexpected response code ' + res.statusCode);
			callback_fail(false);
		}
	});
	req.setHeader('Content-Type', contentType);
	req.setHeader('X-Restchain-Public-Key', pubkey);
	req.setHeader('X-Restchain-Signature', signature);
	req.on('error', function(e) {
		console.log('Error: ' + e);
		callback_fail(false);
	});
	if (body) req.write(body);
	req.end();
}
/* End of RESTchain ACL Standard Library */
