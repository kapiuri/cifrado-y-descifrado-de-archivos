import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

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

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cifrado y Firma")
        self.root.geometry("600x500")

        # Estilo
        self.style = ttk.Style()
        self.style.configure('TButton', padding=6, relief="flat", background="#ccc")
        self.style.configure('TLabel', font=('Arial', 10, 'bold'))

        # Crear widgets
        self.create_widgets()

    def create_widgets(self):
        # Sección de Cifrado Simétrico (AES)
        ttk.Label(self.root, text="Cifrado Simétrico (AES)", font=('Arial', 12, 'bold')).pack(pady=10)
        ttk.Button(self.root, text="Cifrar Archivo (AES)", command=self.encrypt_file_aes).pack(pady=5)
        ttk.Button(self.root, text="Descifrar Archivo (AES)", command=self.decrypt_file_aes).pack(pady=5)

        # Sección de Cifrado Asimétrico (RSA) y Firma
        ttk.Label(self.root, text="Cifrado Asimétrico y Firma Digital", font=('Arial', 12, 'bold')).pack(pady=10)
        ttk.Button(self.root, text="Generar Claves RSA", command=self.generate_key_pair).pack(pady=5)
        ttk.Button(self.root, text="Cifrar Archivo (RSA)", command=self.encrypt_file_rsa).pack(pady=5)
        ttk.Button(self.root, text="Descifrar Archivo (RSA)", command=self.decrypt_file_rsa).pack(pady=5)
        ttk.Button(self.root, text="Firmar Archivo", command=self.sign_file).pack(pady=5)
        ttk.Button(self.root, text="Verificar Firma", command=self.verify_signature).pack(pady=5)

        self.info_text = scrolledtext.ScrolledText(self.root, width=80, height=15, wrap=tk.WORD)
        self.info_text.pack(pady=10)

    def update_info(self, message):
        self.info_text.insert(tk.END, message + '\n')
        self.info_text.yview(tk.END)

    # Cifrado Simétrico (AES) Methods
    def encrypt_file_aes(self):
        filepath = filedialog.askopenfilename(title="Seleccionar archivo a cifrar")
        if filepath:
            key = get_random_bytes(16)  # Generate a 16-byte (128-bit) key
            AESCipher.encrypt_file(filepath, key)
            with open(filepath + '.key', 'wb') as key_file:
                key_file.write(key)
            self.update_info(f"Archivo cifrado como {filepath}.enc\nClave guardada como {filepath}.key")

    def decrypt_file_aes(self):
        filepath = filedialog.askopenfilename(title="Seleccionar archivo cifrado")
        if filepath:
            key_filepath = filedialog.askopenfilename(title="Seleccionar archivo de clave")
            if key_filepath:
                with open(key_filepath, 'rb') as key_file:
                    key = key_file.read()
                AESCipher.decrypt_file(filepath, key)
                self.update_info(f"Archivo descifrado como {filepath[:-4]}")

    # Cifrado Asimétrico (RSA) Methods
    def generate_key_pair(self):
        private_key, public_key = RSACipher.generate_key_pair()

        private_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")], title="Guardar clave privada")
        public_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")], title="Guardar clave pública")

        if private_key_path and public_key_path:
            RSACipher.save_key(private_key, private_key_path, is_private=True)
            RSACipher.save_key(public_key, public_key_path, is_private=False)
            self.update_info("Claves RSA generadas y guardadas exitosamente.")
        else:
            messagebox.showwarning("Advertencia", "No se guardaron las claves.")

    def encrypt_file_rsa(self):
        input_file_path = filedialog.askopenfilename(title="Seleccionar archivo a cifrar")
        output_file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")], title="Guardar archivo cifrado")
        public_key_path = filedialog.askopenfilename(title="Seleccionar clave pública")

        if input_file_path and output_file_path and public_key_path:
            public_key = RSACipher.load_public_key(public_key_path)
            ciphertext = RSACipher.encrypt_file(input_file_path, public_key)
            with open(output_file_path, 'wb') as f:
                f.write(ciphertext)
            self.update_info("Archivo cifrado exitosamente.")
        else:
            messagebox.showwarning("Advertencia", "No se realizó el cifrado.")

    def decrypt_file_rsa(self):
        input_file_path = filedialog.askopenfilename(title="Seleccionar archivo cifrado")
        output_file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")], title="Guardar archivo descifrado")
        private_key_path = filedialog.askopenfilename(title="Seleccionar clave privada")

        if input_file_path and output_file_path and private_key_path:
            private_key = RSACipher.load_private_key(private_key_path)
            plaintext = RSACipher.decrypt_file(input_file_path, private_key)
            with open(output_file_path, 'wb') as f:
                f.write(plaintext)
            self.update_info("Archivo descifrado exitosamente.")
        else:
            messagebox.showwarning("Advertencia", "No se realizó el descifrado.")

    # Firma Digital Methods
    def sign_file(self):
        input_file_path = filedialog.askopenfilename(title="Seleccionar archivo a firmar")
        signature_file_path = filedialog.asksaveasfilename(defaultextension=".sig", filetypes=[("Signature files", "*.sig")], title="Guardar firma")
        private_key_path = filedialog.askopenfilename(title="Seleccionar clave privada")

        if input_file_path and signature_file_path and private_key_path:
            private_key = RSACipher.load_private_key(private_key_path)
            with open(input_file_path, 'rb') as f:
                data = f.read()
            signature = DigitalSignature.sign_file(input_file_path, private_key)
            with open(signature_file_path, 'wb') as f:
                f.write(signature)
            self.update_info("Archivo firmado exitosamente.")
        else:
            messagebox.showwarning("Advertencia", "No se realizó la firma.")

    def verify_signature(self):
        input_file_path = filedialog.askopenfilename(title="Seleccionar archivo firmado")
        signature_file_path = filedialog.askopenfilename(title="Seleccionar archivo de firma")
        public_key_path = filedialog.askopenfilename(title="Seleccionar clave pública")

        if input_file_path and signature_file_path and public_key_path:
            public_key = RSACipher.load_public_key(public_key_path)
            with open(input_file_path, 'rb') as f:
                data = f.read()
            with open(signature_file_path, 'rb') as f:
                signature = f.read()
            if DigitalSignature.verify_signature(data, signature, public_key):
                self.update_info("La firma es válida.")
            else:
                self.update_info("La firma no es válida.")
        else:
            messagebox.showwarning("Advertencia", "No se realizó la verificación.")

# Crear la ventana principal y ejecutar la aplicación
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
