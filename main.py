from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Block size for AES (16 bytes for AES-128)
BLOCK_SIZE = 16

def pad(data):
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length]) * padding_length

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(filepath, key):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(filepath, 'rb') as file:
        plaintext = file.read()

    padded_plaintext = pad(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)

    with open(filepath + '.enc', 'wb') as file:
        file.write(cipher.iv)  # Save the IV at the beginning of the encrypted file
        file.write(ciphertext)

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

def select_file(action):
    filepath = filedialog.askopenfilename()
    if filepath:
        if action == 'encrypt':
            key = get_random_bytes(16)  # Generate a 16-byte (128-bit) key
            encrypt_file(filepath, key)
            with open(filepath + '.key', 'wb') as key_file:
                key_file.write(key)
            messagebox.showinfo("Success", f"File encrypted as {filepath}.enc\nKey saved as {filepath}.key")
        elif action == 'decrypt':
            key_filepath = filedialog.askopenfilename(title="Select Key File")
            if key_filepath:
                with open(key_filepath, 'rb') as file:
                    key = file.read()
                decrypt_file(filepath, key)
                messagebox.showinfo("Success", f"File decrypted as {filepath[:-4]}")

def main():
    root = tk.Tk()
    root.title("File Encryption and Decryption")
    root.geometry("400x200")
    root.configure(bg="#f0f0f0")  # Light gray background

    # Title
    title_label = tk.Label(root, text="File Encryption and Decryption", font=("Helvetica", 16), bg="#f0f0f0")
    title_label.pack(pady=20)

    # Button to encrypt
    encrypt_button = ttk.Button(root, text="Encrypt File", command=lambda: select_file('encrypt'))
    encrypt_button.pack(pady=10, padx=20, fill='x')

    # Button to decrypt
    decrypt_button = ttk.Button(root, text="Decrypt File", command=lambda: select_file('decrypt'))
    decrypt_button.pack(pady=10, padx=20, fill='x')

    root.mainloop()

if __name__ == "__main__":
    main()
