from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def gen_key_pair(password=None):
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=4096,
		backend=default_backend()
	)
	
	key_encryption_algorithm = serialization.NoEncryption()

	if password:
		if not isinstance(password,bytes):
			password = password.encode('utf-8')
		key_encryption_algorithm = serialization.BestAvailableEncryption(password)

	private_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=key_encryption_algorithm
	)

	public_key = private_key.public_key()

	public_pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	return private_pem, public_pem

def write_to_file(key_name,keys):
	pvt_name = f'{key_name}_private.pem'
	with open(pvt_name, 'wb') as pvt:
		pvt.write(keys[0])

	pub_name = f'{key_name}_public.pem'
	with open(pub_name, 'wb') as pub:
		pub.write(keys[1])

if __name__ == '__main__':
	with open('key_name','r') as key:
		key_name = key.read()

	with open('pwd','rb') as pwd:
		password = pwd.read()

	keys = gen_key_pair(password)
	write_to_file(key_name,keys)