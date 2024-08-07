# cipherrsa.py

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend

class RSACipher:
    @staticmethod
    def generate_key_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_key(key, path, is_private=True):
        if is_private:
            key_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=BestAvailableEncryption(b"password")
            )
        else:
            key_bytes = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        with open(path, 'wb') as f:
            f.write(key_bytes)

    @staticmethod
    def load_public_key(path):
        with open(path, 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    @staticmethod
    def load_private_key(path):
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=b"password", backend=default_backend())

    @staticmethod
    def encrypt_file(filepath, public_key):
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        ciphertext = public_key.encrypt(
            plaintext,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    @staticmethod
    def decrypt_file(filepath, private_key):
        with open(filepath, 'rb') as f:
            ciphertext = f.read()
        plaintext = private_key.decrypt(
            ciphertext,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
