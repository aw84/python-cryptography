from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key(public_exponent=65537, key_size=1024 * 4, backend=default_backend()):
    return rsa.generate_private_key(public_exponent, key_size, backend)


def write_key_to_file(filename, key):
    with open(filename, "wb") as key_file:
        key_file.write(key)
        key_file.close()


def read_public_key(filename):
    with open(filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        return public_key


def read_private_key(filename, password):
    with open(filename, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
        key_file.close()
    return private_key


def save_key_pair(key, password, prefix):
    write_key_to_file(
        "{}_private.pem".format(prefix),
        serialize_private_key(key, password))
    write_key_to_file(
        "{}_public.pem".format(prefix),
        serialize_public_key(key))


def serialize_private_key(key, private_key_password):
    pem_priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(private_key_password))
    return pem_priv


def serialize_public_key(key):
    public_key = key.public_key()
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem_pub
