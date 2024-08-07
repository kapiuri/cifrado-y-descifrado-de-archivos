# main.py

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext, simpledialog
from cipheraes import AESCipher
from cipherrsa import RSACipher
from signature import DigitalSignature
from hashing import hash_file, save_hash, load_hash, verify_hash
from Crypto.Random import get_random_bytes

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cifrado, Firma y Hashing")
        self.root.geometry("600x600")

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

        # Sección de Hashing
        ttk.Label(self.root, text="Hashing SHA-256", font=('Arial', 12, 'bold')).pack(pady=10)
        ttk.Button(self.root, text="Generar Hash de Archivo", command=self.hash_file).pack(pady=5)
        ttk.Button(self.root, text="Verificar Hash de Archivo", command=self.verify_file_hash).pack(pady=5)

        self.info_text = scrolledtext.ScrolledText(self.root, width=80, height=20, wrap=tk.WORD)
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

    # Hashing Methods
    def hash_file(self):
        filepath = filedialog.askopenfilename(title="Seleccionar archivo para hash")
        if filepath:
            file_hash = hash_file(filepath)
            if file_hash:
                hash_file_path = filedialog.asksaveasfilename(defaultextension=".hash", filetypes=[("Hash files", "*.hash")], title="Guardar archivo de hash")
                if hash_file_path:
                    save_hash(hash_file_path, file_hash)
                    self.update_info(f"Hash del archivo generado y guardado en {hash_file_path}")
                else:
                    self.update_info("No se guardó el archivo de hash.")
            else:
                self.update_info("No se pudo calcular el hash del archivo.")

    def verify_file_hash(self):
        filepath = filedialog.askopenfilename(title="Seleccionar archivo para verificar hash")
        if filepath:
            hash_file_path = filedialog.askopenfilename(title="Seleccionar archivo de hash")
            if hash_file_path:
                expected_hash = load_hash(hash_file_path)
                if expected_hash:
                    if verify_hash(filepath, expected_hash):
                        self.update_info("El hash del archivo coincide con el valor esperado.")
                    else:
                        self.update_info("El hash del archivo NO coincide con el valor esperado.")
                else:
                    self.update_info("No se pudo cargar el hash desde el archivo.")
            else:
                messagebox.showwarning("Advertencia", "No se seleccionó el archivo de hash.")

# Crear la ventana principal y ejecutar la aplicación
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
