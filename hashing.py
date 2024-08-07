# hashing.py

import hashlib

def hash_file(filepath):
    """Genera un hash SHA-256 para el contenido del archivo."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hash_sha256.update(chunk)
    except FileNotFoundError:
        return None
    return hash_sha256.hexdigest()

def save_hash(filepath, hash_value):
    """Guarda el hash en un archivo."""
    with open(filepath, 'w') as f:
        f.write(hash_value)

def load_hash(filepath):
    """Carga el hash desde un archivo."""
    try:
        with open(filepath, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

def verify_hash(filepath, expected_hash):
    """Verifica si el hash SHA-256 del archivo coincide con el hash esperado."""
    file_hash = hash_file(filepath)
    if file_hash is None:
        return False
    return file_hash == expected_hash
