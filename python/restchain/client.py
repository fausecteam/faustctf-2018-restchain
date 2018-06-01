#!/usr/bin/env python3

import logging
import requests
import string

BLOCK_HEADER_PREFIX = 'X-Restchain-Block-'
GENESIS_BLOCK_ID = '6666666666666666666666666666666666666666666666666666666666666666'

class RESTchainError(Exception):
	def r(self, response=None):
		if response is not None:
			self._last_response = response
			return self
		else:
			return getattr(self, '_last_response', None)

class RESTchainBlockPermissionDenied(RESTchainError):
	def __init__(self, message, block_stub):
		super().__init__(message)
		self.block_stub = block_stub

class RESTchainBlockNotFound(RESTchainError):
	pass

class RESTchainClient:
	def __init__(self, api_base='http://localhost:6060/api'):
		self._api_base = api_base

	def __repr__(self):
		return '<RESTchainClient {}>'.format(repr(self._api_base))

	def api_url(self, *params):
		return '/'.join([self._api_base] + list(params))

	def generate_private_key(self):
		res = requests.get(self.api_url('crypto/privatekey'))
		if res.status_code != 200:
			raise RESTchainError('generating private key failed: {}: {}'.format(res, res.text)).r(res)
		try:
			return res.headers['X-Restchain-Private-Key'], res.headers['X-Restchain-Public-Key']
		except KeyError as e:
			raise RESTchainError('invalid response headers').r(res) from e

	def sign(self, private_key, message):
		headers = {}
		headers['X-Restchain-Private-Key'] = private_key
		if isinstance(message, RESTchainSignedData):
			message._set_headers(headers)
			res = requests.post(self.api_url('crypto/sign'), headers=headers, data=message.body)
		else:
			headers['X-Restchain-Raw-Data'] = message
			res = requests.post(self.api_url('crypto/sign'), headers=headers)
		if res.status_code != 200:
			raise RESTchainError('signing failed: {}: {}'.format(res, res.text)).r(res)
		try:
			return res.headers['X-Restchain-Signature']
		except KeyError as e:
			raise RESTchainError('invalid response headers').r(res) from e

	def verify(self, public_key, message, signature):
		headers = {}
		headers['X-Restchain-Public-Key'] = public_key
		headers['X-Restchain-Signature'] = signature
		if isinstance(message, RESTchainSignedData):
			message._set_headers(headers)
			res = requests.post(self.api_url('crypto/verify'), headers=headers, data=message.body)
		else:
			headers['X-Restchain-Raw-Data'] = message
			res = requests.post(self.api_url('crypto/verify'), headers=headers)
		if res.status_code == 200 and res.text.strip() == 'OK':
			return True
		elif res.status_code == 418 and res.text.strip() == 'FAIL':
			return False
		else:
			raise RESTchainError('verifying failed: {}: {}'.format(res, res.text)).r(res)

	def get_block_id(self, signed_data, previous, public_key, signature):
		headers = signed_data._get_headers()
		headers['X-Restchain-Previous'] = previous
		headers['X-Restchain-Signer'] = public_key
		headers['X-Restchain-Signature'] = signature
		res = requests.post(self.api_url('crypto/blockid'), headers=headers, data=signed_data.body)
		if res.status_code != 200:
			raise RESTchainError('hashing block failed: {}: {}'.format(res, res.text)).r(res)
		return res.text.strip()

	def get_block(self, block_id, headers=None):
		res = requests.get(self.api_url('block', block_id), headers=headers)
		if res.status_code == 403:
			try:
				RESTchainBlock.from_response(block_id, res)
			except RESTchainBlockPermissionDenied:
				raise
			else:
				assert False
		elif res.status_code == 404:
			raise RESTchainBlockNotFound('block {} not found: {}'.format(block_id, res))
		elif res.status_code != 200:
			raise RESTchainError('getting block failed: {}: {}'.format(res, res.text)).r(res)
		return RESTchainBlock.from_response(block_id, res)

	def put_block(self, previous, data, private_key, public_key):
		if isinstance(previous, RESTchainBlock):
			previous = previous.block_id
		signature = self.sign(private_key, data)
		headers = data._get_headers()
		headers['X-Restchain-Previous'] = previous
		headers['X-Restchain-Signer'] = public_key
		headers['X-Restchain-Signature'] = signature
		res = requests.put(self.api_url('block'), headers=headers, data=data.body, allow_redirects=False)
		if res.status_code not in {200, 303}:
			raise RESTchainError('putting block failed: {}: {}'.format(res, res.text)).r(res)
		try:
			block_id = res.headers['X-Restchain-Id']
		except KeyError as e:
			raise RESTchainError('invalid response headers').r(res) from e
		assert len(block_id) == len(GENESIS_BLOCK_ID)
		assert all(c in string.hexdigits for c in block_id)
		return RESTchainBlock(block_id, previous, data, public_key, signature)

	def list_acls(self):
		res = requests.get(self.api_url('acl'))
		if res.status_code != 200:
			raise RESTchainError('getting block failed: {}: {}'.format(res, res.text)).r(res)
		return res.text.split()

	def get_acl(self, acl_name, params=None):
		res = requests.get(self.api_url('acl', acl_name), params=params)
		if res.status_code != 200:
			raise RESTchainError('getting block failed: {}: {}'.format(res, res.text)).r(res)
		return res.text.strip()

class RESTchainSignedData:
	def __init__(self, body='', headers=None, content_type='text/plain'):
		if headers is None:
			headers = {}

		self.headers = {canonical_header(k): v for k, v in headers.items()}
		self.content_type = content_type
		self.body = body

	def __repr__(self):
		return '<RESTchainSignedData {} {} {}>'.format(
				repr(self.headers),
				repr(self.content_type),
				repr(self.body)
				)

	def __eq__(self, other):
		return type(self) == type(other) \
				and self.headers == other.headers \
				and self.content_type == other.content_type \
				and self.body == other.body

	def get_header(self, name):
		return self.headers.get(canonical_header(name), None)

	def set_header(self, name, value):
		self.headers[canonical_header(name)] = value

	def del_header(self, name):
		del self.headers[canonical_header(name)]
	
	def _get_headers(self):
		headers = {BLOCK_HEADER_PREFIX + k: v for k, v in self.headers.items()}
		headers['Content-Type'] = self.content_type
		return headers

	def _set_headers(self, d):
		for k, v in self._get_headers().items():
			d[k] = v

class RESTchainBlock:
	def __init__(self, block_id, previous, signed_data, signer, signature):
		self.block_id = block_id
		self.previous = previous
		self.signed_data = signed_data
		self.signer = signer
		self.signature = signature

	@classmethod
	def from_response(cls, block_id, response):
		try:
			previous = response.headers['X-Restchain-Previous']
			signer = response.headers['X-Restchain-Signer']
			signature = response.headers['X-Restchain-Signature']
		except KeyError as e:
			raise RESTchainError('invalid response headers').r(response) from e
		if response.status_code == 200:
			body = response.text
			headers = {k[len(BLOCK_HEADER_PREFIX):]: v for k, v in response.headers.items() if k.startswith(BLOCK_HEADER_PREFIX)}
			try:
				content_type = response.headers['Content-Type']
			except KeyError as e:
				raise RESTchainError('invalid response headers').r(response) from e
			signed_data = RESTchainSignedData(body, headers, content_type)
			return RESTchainBlock(block_id, previous, signed_data, signer, signature)
		elif response.status_code == 403:
			try:
				payload_hash = response.headers['X-Restchain-Payload-Hash']
			except KeyError as e:
				raise RESTchainError('invalid response headers').r(response) from e
			block = RESTchainBlock(block_id, previous, payload_hash, signer, signature)
			raise RESTchainBlockPermissionDenied("access to block payload denied", block)
		else:
			raise ValueError()

	def __repr__(self):
		return '<RESTchainBlock {} {} {}>'.format(
				repr(self.block_id),
				repr(self.signed_data),
				repr(self.signature)
				)

	def __eq__(self, other):
		return type(self) == type(other) \
				and self.block_id == other.block_id \
				and self.previous == other.previous \
				and self.signed_data == other.signed_data \
				and self.signer == other.signer \
				and self.signature == other.signature

	@property
	def content_type(self):
		if self.signed_data is None:
			return None
		return self.signed_data.content_type

	@property
	def body(self):
		if self.signed_data is None:
			return None
		return self.signed_data.body

def canonical_header(n):
	return ''.join(n[i].upper() if i == 0 or n[i-1] == '-' else n[i].lower() for i in range(len(n)))

def enable_debug():
	import http.client
	http.client.HTTPConnection.debuglevel = 1
	logging.basicConfig()
	logging.getLogger().setLevel(logging.DEBUG)
	requests_log = logging.getLogger("requests.packages.urllib3")
	requests_log.setLevel(logging.DEBUG)
	requests_log.propagate = True

def main():
	import sys

	#enable_debug()

	try:
		c = RESTchainClient(sys.argv[1])
	except IndexError:
		c = RESTchainClient()

	print(c)
	print()

	priv, pub = c.generate_private_key()
	print('public key:', pub)
	print('private key:', priv)
	print()

	msg = RESTchainSignedData(body='Hello World')
	msg.set_header('X-Test', '42')
	msg.set_header('X-Test-A', '23')
	msg.set_header('X-Test-B', '1337')
	#msg.set_header('Ld-Preload', 'pwn.so')
	print(msg)
	sig = c.sign(priv, msg)
	print('signature:', sig)
	print()

	print('verify:', c.verify(pub, msg, sig))
	msg.del_header('X-Test')
	print('verify (tampered):', c.verify(pub, msg, sig))
	print()

	block = GENESIS_BLOCK_ID
	for i in range(3):
		block = c.put_block(block, msg, priv, pub)
		print('put block:', block)
		assert c.get_block_id(block.signed_data, block.previous, pub, block.signature) == block.block_id
	print()

	block = c.get_block(block.block_id)
	print(block)
	print()

	print('available acls:', c.list_acls())
	print()

	acl_secret = c.get_acl('require-secret', {'secret': 'faust666!'})
	print('acl require-secret:', acl_secret)
	msg.set_header('Acl', acl_secret)
	block = c.put_block(block, msg, priv, pub)
	try:
		block = c.get_block(block.block_id)
		raise Exception('got block without providing secret')
	except RESTchainBlockPermissionDenied as e:
		print('requesting block without access token:', e, e.block_stub)
	block = c.get_block(block.block_id, {'X-Restchain-Acl-Secret': 'faust666!'})
	print('requesting block with access tocken:', block)
	print()

	acl_signature = c.get_acl('require-signature', {'key[FAUST]': pub})
	print('acl require-signature:', acl_signature)
	msg.set_header('Acl', acl_signature)
	block = c.put_block(block, msg, priv, pub)
	try:
		block = c.get_block(block.block_id)
		raise Exception('got block without providing signature')
	except RESTchainBlockPermissionDenied as e:
		print('requesting block without access signature:', e, e.block_stub)

	access_sig =c.sign(priv, RESTchainSignedData(content_type='application/vnd.faust.faustctf-2018-restchain-access-signature'))
	print('access signature:', access_sig)
	block = c.get_block(block.block_id, {'X-Restchain-Acl-Key-Id': 'FAUST', 'X-Restchain-Acl-Signature': access_sig})
	print('requesting block with access tocken:', block)
	print()

	try:
		block = c.get_block('0')
	except RESTchainBlockNotFound as e:
		print('retrieving non-existant block:', repr(e))
	else:
		print('could retrieve non-existant block:', block)

if __name__ == '__main__':
	main()
