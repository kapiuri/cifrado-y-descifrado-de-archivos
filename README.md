# Aplicación de Cifrado y Firma Digital en Python

Esta aplicación, desarrollada en Python utilizando Tkinter y las bibliotecas `cryptography` y `pycryptodome`, proporciona funcionalidades para cifrar y descifrar archivos utilizando cifrado simétrico (AES) y asimétrico (RSA), así como para firmar y verificar firmas digitales.

## Requisitos

- Python 3.6 o superior
- Paquetes Python: `tkinter`, `cryptography`, `pycryptodome`

## Instalación

1. **Clonar el repositorio** o descargar el archivo Python.
2. **Instalar las dependencias** usando pip:

    ```bash
    pip install cryptography pycryptodome
    ```

## Uso

1. **Ejecuta la aplicación**. Puedes hacerlo ejecutando el archivo Python en tu terminal o desde un entorno de desarrollo:

    ```bash
    python main.py
    ```

2. **Interfaz de Usuario**:
   - **Cifrado Simétrico (AES)**:
     - **Cifrar Archivo (AES)**: Selecciona el archivo a cifrar. La aplicación generará una clave aleatoria, cifrará el archivo usando AES y guardará la clave en un archivo `.key`.
     - **Descifrar Archivo (AES)**: Selecciona el archivo cifrado y el archivo de clave correspondiente. La aplicación descifrará el archivo y lo guardará con el nombre original.

   - **Cifrado Asimétrico (RSA) y Firma Digital**:
     - **Generar Claves RSA**: Genera un par de claves RSA (pública y privada) y las guarda en archivos `.pem`.
     - **Cifrar Archivo (RSA)**: Selecciona el archivo a cifrar y la clave pública. La aplicación cifrará el archivo usando RSA.
     - **Descifrar Archivo (RSA)**: Selecciona el archivo cifrado y la clave privada. La aplicación descifrará el archivo.
     - **Firmar Archivo**: Selecciona el archivo a firmar y la clave privada. La aplicación generará una firma digital y la guardará en un archivo `.sig`.
     - **Verificar Firma**: Selecciona el archivo firmado, el archivo de firma y la clave pública. La aplicación verificará la validez de la firma.

## Detalles Técnicos

### Cifrado Simétrico (AES)
- **Método**: `AES.MODE_CBC` con padding para asegurar el tamaño del bloque.
- **Archivo Cifrado**: Guardado con extensión `.enc`.
- **Archivo de Clave**: Guardado con extensión `.key`.

### Cifrado Asimétrico (RSA)
- **Generación de Claves**: Claves RSA de 2048 bits.
- **Cifrado y Descifrado**: Usando padding OAEP con SHA-256.
- **Archivos de Claves**: Claves públicas y privadas guardadas en formato PEM.

### Firma Digital
- **Método**: RSA con padding PSS y SHA-256.
- **Archivo de Firma**: Guardado con extensión `.sig`.

## Código

### Archivo Python (`tu_archivo.py`)

- **Clases Principales**:
  - `AESCipher`: Métodos para cifrar y descifrar archivos usando AES.
  - `RSACipher`: Métodos para generar claves RSA, cifrar y descifrar archivos usando RSA.
  - `DigitalSignature`: Métodos para firmar y verificar firmas digitales.
  - `CryptoApp`: Interfaz gráfica de usuario para interactuar con las funcionalidades de cifrado y firma.

## Ejemplo de Uso

1. **Cifrar un archivo con AES**:
   - Selecciona "Cifrar Archivo (AES)".
   - Elige el archivo que deseas cifrar.
   - Guarda el archivo cifrado y la clave generada.

2. **Firmar un archivo con RSA**:
   - Selecciona "Firmar Archivo".
   - Elige el archivo que deseas firmar.
   - Guarda la firma generada.

3. **Verificar una firma digital**:
   - Selecciona "Verificar Firma".
   - Elige el archivo firmado, el archivo de firma y la clave pública.
   - La aplicación te informará si la firma es válida o no.
