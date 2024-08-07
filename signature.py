# signature.py

from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

class DigitalSignature:
    @staticmethod
    def sign_file(filepath, private_key):
        with open(filepath, 'rb') as f:
            data = f.read()
        signature = private_key.sign(
            data,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(data, signature, public_key):
        try:
            public_key.verify(
                signature,
                data,
                rsa_padding.PSS(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    salt_length=rsa_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
