# Aplicación de Cifrado, Firma Digital y Hash en Python

Esta aplicación, desarrollada en Python utilizando Tkinter y las bibliotecas `cryptography` y `pycryptodome`, proporciona funcionalidades para cifrar y descifrar archivos utilizando cifrado simétrico (AES) y asimétrico (RSA), así como para firmar y verificar firmas digitales. También permite generar y verificar hashes SHA-256 de archivos.

## Requisitos

- Python 3.6 o superior
- Paquetes Python: `tkinter`, `cryptography`, `pycryptodome`

## Instalación

1. Clona el repositorio o descarga los archivos Python.

2. Instala las dependencias usando pip:

    ```bash
    pip install cryptography pycryptodome
    ```

## Uso

Para ejecutar la aplicación, abre tu terminal y navega a la carpeta que contiene `main.py`. Luego, ejecuta el siguiente comando:

```bash
python main.py
```

## Interfaz de Usuario

La aplicación se abre con una **interfaz gráfica** intuitiva que te permite realizar las siguientes operaciones:

### 🔐 Cifrado Simétrico (AES)

- **Cifrar Archivo (AES)**:
  1. **Selecciona** el archivo que deseas cifrar.
  2. La aplicación **generará una clave aleatoria**, cifrará el archivo usando AES, y **guardará la clave en un archivo `.key`**.
  3. El archivo cifrado se guardará con la extensión `.enc`.

- **Descifrar Archivo (AES)**:
  1. **Selecciona** el archivo cifrado `.enc` y el archivo de clave `.key`.
  2. La aplicación **descifrará el archivo** y lo guardará con el nombre original.

### 🔒 Cifrado Asimétrico (RSA) y Firma Digital

- **Generar Claves RSA**:
  1. **Genera** un par de claves RSA (pública y privada) y las **guarda en archivos `.pem`**.
  2. La **clave privada** se usa para cifrar y firmar, mientras que la **clave pública** se usa para descifrar y verificar.

- **Cifrar Archivo (RSA)**:
  1. **Selecciona** el archivo que deseas cifrar y la clave pública `.pem`.
  2. La aplicación **cifrará el archivo usando RSA**.
  3. El archivo cifrado se guardará con la extensión `.enc`.

- **Descifrar Archivo (RSA)**:
  1. **Selecciona** el archivo cifrado `.enc` y la clave privada `.pem`.
  2. La aplicación **descifrará el archivo** y lo guardará con el nombre original.

- **Firmar Archivo**:
  1. **Selecciona** el archivo que deseas firmar y la clave privada `.pem`.
  2. La aplicación **generará una firma digital** y la **guardará en un archivo `.sig`**.

- **Verificar Firma**:
  1. **Selecciona** el archivo firmado, el archivo de firma `.sig`, y la clave pública `.pem`.
  2. La aplicación **verificará la validez de la firma** y te informará si es válida o no.

### 🛡️ Hashing SHA-256

- **Generar Hash de Archivo**:
  1. **Selecciona** el archivo para calcular su hash SHA-256.
  2. La aplicación **guardará el hash en un archivo `.hash`**.

- **Verificar Hash de Archivo**:
  1. **Selecciona** el archivo cuyo hash deseas verificar y el archivo de hash `.hash` que contiene el hash esperado.
  2. La aplicación **comparará el hash del archivo** con el valor esperado y te informará si coincide o no.

## Archivos del Proyecto

- **`main.py`**: Contiene la interfaz gráfica de usuario y la lógica para cifrar, descifrar, firmar, verificar firmas y manejar hashes de archivos. Este es el archivo principal que ejecutas para iniciar la aplicación.

- **`signature.py`**: Define la clase `DigitalSignature` que proporciona métodos para firmar archivos y verificar firmas digitales.

- **`cipherrsa.py`**: Define la clase `RSACipher` que proporciona métodos para generar claves RSA, cifrar y descifrar archivos usando RSA.

- **`cipheraes.py`**: Define la clase `AESCipher` que proporciona métodos para cifrar y descifrar archivos usando AES.

- **`hashing.py`**: Define funciones para generar y verificar hashes SHA-256 de archivos.

## Ejemplo de Uso

### Cifrar un archivo con AES:

1. Abre la aplicación.
2. Selecciona "Cifrar Archivo (AES)".
3. Elige el archivo que deseas cifrar.
4. Guarda el archivo cifrado y la clave generada.

### Firmar un archivo con RSA:

1. Abre la aplicación.
2. Selecciona "Firmar Archivo".
3. Elige el archivo que deseas firmar.
4. Guarda la firma generada en un archivo `.sig`.

### Verificar una firma digital:

1. Abre la aplicación.
2. Selecciona "Verificar Firma".
3. Elige el archivo firmado, el archivo de firma `.sig`, y la clave pública `.pem`.
4. La aplicación te informará si la firma es válida o no.

### Generar y verificar un hash SHA-256:

- **Generar Hash**:
  1. Selecciona "Generar Hash de Archivo".
  2. Elige el archivo para calcular su hash SHA-256.
  3. Guarda el hash en un archivo `.hash`.

- **Verificar Hash**:
  1. Selecciona "Verificar Hash de Archivo".
  2. Elige el archivo cuyo hash deseas verificar y el archivo `.hash` que contiene el hash esperado.
  3. La aplicación comparará el hash del archivo con el valor esperado.
