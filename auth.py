from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def get_key_name(filename='key_name'):
	with open('key_name', 'r') as key:
		key_name = key.read()
	return key_name

def get_private_key(password=None):
	key_name = get_key_name()
	
	if password:
		if not isinstance(password,bytes):
			password = password.encode('utf-8')
		key_encryption_algorithm = serialization.BestAvailableEncryption(password)
	
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

def verify(signature,construct,**kgars):
	try:
		public_key = kgars['public_key']
	except:
		private_key = get_private_key()
		public_key = private_key.public_key()

	if not isinstance(construct,bytes):
		construct = construct.encode('utf-8')
	try:
		public_key.verify(
			signature,
			construct,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
				),
			hashes.SHA256()
			)
	except:
		return False
	return True

if __name__ == '__main__':
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