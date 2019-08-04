import base64
import getpass
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# openssl rsautl -encrypt -in Dockerfile -out cipher.txt -pubin -inkey public.pem
# openssl rsautl -decrypt -in cipher.txt -out 1.dockerfile -inkey private.pem
from helper.AsymetricKey import read_public_key, read_private_key

block_size_bytes = 16


def rsa_encrypt(key, message):
    ciphertext = key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return ciphertext


def rsa_decrypt(key, ciphertext):
    msg = key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    return msg


def encrypt(key, data):
    """
    public_key is used only to encrypt one-time password provied to AES
    """
    aes_key = secrets.token_bytes(32)
    aes_iv = secrets.token_bytes(block_size_bytes)
    padder = sym_padding.PKCS7(block_size_bytes * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(aes_iv),
        backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    aes_key_enc = rsa_encrypt(key, aes_key + aes_iv)
    return (aes_key_enc, ciphertext)


def decrypt(rsa_key, aes_key_enc, ciphertext):
    """
    First decrypt AES key and initialization vector, then use decrypted
    artifacts to initialize Cipher
    """
    t = rsa_decrypt(rsa_key, aes_key_enc)
    aes_key = t[:32]
    aes_iv = t[32:]
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(aes_iv),
        backend=default_backend())
    decryptor = cipher.decryptor()
    msg_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(block_size_bytes * 8).unpadder()
    msg = unpadder.update(msg_padded) + unpadder.finalize()
    return msg


def send_session_public_key(session_key):
    print(base64.b64encode(session_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw)))


def recv_peer_public_key(data):
    return X25519PublicKey.from_public_bytes(base64.b64decode(data))


session_key = None


def publish_session_key_exchange():
    global session_key
    session_key = X25519PrivateKey.generate()
    send_session_public_key(session_key)


def generate_session_key(data):
    peer_public_key = recv_peer_public_key(data)
    shared_session_key = session_key.exchange(peer_public_key)
    print(shared_session_key)


if __name__ == '__main__':
    # exit(0)
    # key = generate_key()
    # p = 'abcd' # getpass.getpass()
    # save_key_pair(key, b'abcd', "u1")
    key = read_public_key('u1/u1_public.pem')
    (aes_key_enc, ciphertext) = encrypt(key, b"abc")
    ct_b64enc = base64.b64encode(ciphertext)
    print(ct_b64enc)
    ciphertext = base64.b64decode(ct_b64enc)
    p = getpass.getpass()
    key = read_private_key('u1/u1_private.pem', p.encode())
    msg = decrypt(key, aes_key_enc, ciphertext)
    print(msg)
