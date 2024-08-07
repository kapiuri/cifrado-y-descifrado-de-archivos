# cipheraes.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Block size for AES (16 bytes for AES-128)
BLOCK_SIZE = 16

def pad(data):
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length]) * padding_length

def unpad(data):
    return data[:-data[-1]]

class AESCipher:
    @staticmethod
    def encrypt_file(filepath, key):
        cipher = AES.new(key, AES.MODE_CBC)
        with open(filepath, 'rb') as file:
            plaintext = file.read()

        padded_plaintext = pad(plaintext)
        ciphertext = cipher.encrypt(padded_plaintext)

        with open(filepath + '.enc', 'wb') as file:
            file.write(cipher.iv)  # Save the IV at the beginning of the encrypted file
            file.write(ciphertext)

    @staticmethod
    def decrypt_file(filepath, key):
        with open(filepath, 'rb') as file:
            iv = file.read(16)  # IV is 16 bytes
            ciphertext = file.read()

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext)

        output_filename = filepath[:-4]  # Remove '.enc'
        with open(output_filename, 'wb') as file:
            file.write(plaintext)
