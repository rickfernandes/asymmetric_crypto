# -*- coding: utf-8 -*-
"""
This module uses a private and/or public key to encypt/decrypt payloads.

__External modules__: `cryptography`

`Compatible with Python3.7 or higher`\n

_Repository:_ https://github.com/rickfernandes/asymmetric_crypto
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def get_key_name(filename='key_name'):
	"""Fuction to get the key name saved on the file `key_name`

	Args:
		filename (str): Optional filename to be used, default: _key_name_

	Returns:
		key_name (str): content of `key_name` file
    """
	with open(filename, 'r') as key:
		key_name = key.read()
	return key_name

def get_private_key(password=None):
	"""Fuction to get the private key from .pem file, decrypts the key using `password`
	Automatically adds `_private` to the end of the key_name when fetching.
	The filename pattern to be used is key_name_private.pem

	Args:
		password (bytes): password to be used when decrypting the key
		or
		password (str): password to be used when decrypting the key

	Returns:
		private_key (_RSAPrivateKey): if `success` loading the key\n
		None (None): if else
    """
	key_name = get_key_name()
	
	if password:
		if not isinstance(password,bytes):
			password = password.encode('utf-8')
	
	try:
		with open(f'{key_name}_private.pem', 'rb') as key_file:
			private_key = serialization.load_pem_private_key(
				key_file.read(),
				password=password,
				backend = default_backend()
			)
	except:
		private_key = None
	
	return private_key

def get_public_key():
	"""Fuction to get the public key from .pem file.
	Automatically adds `_public` to the end of the key_name when fetching.
	The filename pattern to be used is key_name_public.pem

	Args:
		__None__

	Returns:
		private_key (_RSAPublicKey): if `success` loading the key\n
		None (None): if else
    """
	key_name = get_key_name()
	try:
		with open(f'{key_name}_public.pem', 'rb') as key_file:
			public_key = serialization.load_pem_public_key(
				key_file.read(),
				backend=default_backend()
			)
	except:
		public_key = None
	
	return public_key

def encrypt_payload(payload,**kgars):
	"""Fuction encrypt the `payload` using a `public_key`.
	If no public key is passed with the arguments, uses `get_public_key` method to load it.

	Args:
		payload (str): payload to be encrypted.\n
		public_key (_RSAPublicKey): optional `public_key` (passed in `kwargs`)

	Returns:
		encrypted (bytes): encrypted payload
    """
	try:
		public_key = kgars['public_key']
	except:
		public_key = get_public_key()
	
	message = bytes(payload,'utf-8')
	
	encrypted = public_key.encrypt(
		message,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	return encrypted

def decrypt_payload(encrypted_payload,**kgars):
	"""Fuction decrypt the `pencrypted_ayload` using a `private_key`.
	If no private key is passed with the arguments, uses `get_private_key` method to load it.

	Args:
		encrypted_payload (bytes): encrypted payload to be decrypted.\n
		private_key (_RSAPublicKey): optional `private_key` (passed in `kwargs`)

	Returns:
		decrypted (str): decrypted payload
    """
	try:
		private_key = kgars['private_key']
	except:
		private_key = get_private_key()
	
	try:
		decrypted = private_key.decrypt(
			encrypted_payload,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		).decode('utf-8')
	except:
		decrypted = None
	return decrypted


def sign(payload,**kgars):
	"""Fuction create a encrypted signature for the `payload` using a `private_key`.
	If no private key is passed with the arguments, uses `get_private_key` method to load it.

	Args:
		payload (str): encrypted payload to be decrypted.\n
			or
		payload (bytes): encrypted payload to be decrypted.\n
		private_key (_RSAPublicKey): optional `private_key` (passed in `kwargs`)

	Returns:
		signature (bytes): if success when encrypting = encrypted signature of payload
		None (None): if else
    """
	try:
		private_key = kgars['private_key']
	except:
		private_key = get_private_key()
	
	if not isinstance(payload,bytes):
		payload = payload.encode('utf-8')
	try:
		signature = private_key.sign(
			payload,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
				),
			hashes.SHA256()
			)
	except:
		signature = None

	return signature

def verify(signature,payload,**kgars):
	"""Fuction to verify the `payload` signature using a `public_key`.
	If no public key is passed with the arguments, uses `get_public_key` method to load it.

	Args:
		signature (bytes): encrypted `payload` signature\n
		payload (str): encrypted payload to be decrypted.\n
			or
		payload (bytes): encrypted payload to be decrypted.\n
		public_key (_RSAPublicKey): optional `public_key` (passed in `kwargs`)

	Returns:
		False (boolean): if unsuccessful
		True (boolean): if else
    """
	try:
		public_key = kgars['public_key']
	except:
		private_key = get_private_key()
		public_key = private_key.public_key()

	if not isinstance(payload,bytes):
		payload = payload.encode('utf-8')
	try:
		public_key.verify(
			signature,
			payload,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
				),
			hashes.SHA256()
			)
	except:
		return False
	return True


def _test():
	"""Method to test/debug all functions"""
	with open('pwd','rb') as pwd:
		password = pwd.read()
	pvt = get_private_key(password)
	pub = get_public_key()
	print('pvt',pvt)
	print('pub',pub)
	payload = 'Ricardo Fernandes'
	coded = encrypt_payload(payload,public_key=pub)
	print('coded',coded)
	decoded = decrypt_payload(coded,private_key=pvt)
	print('decoded',decoded)
	sig = sign(payload,private_key=pvt)
	print('sig',sig)
	v = verify(sig,payload,public_key=pub)
	print(v)	

if __name__ == '__main__':
	_test()