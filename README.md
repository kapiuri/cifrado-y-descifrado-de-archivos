# Aplicación de Cifrado y Firma Digital

## Descripción

Esta aplicación de escritorio permite realizar operaciones de cifrado y descifrado de archivos utilizando algoritmos de cifrado simétrico (AES) y asimétrico (RSA), así como firmar y verificar firmas digitales. La interfaz gráfica está construida utilizando Tkinter y las operaciones criptográficas se realizan con las bibliotecas `cryptography` y `pycryptodome`.

## Funcionalidades

### Cifrado Simétrico (AES)

- **Cifrar Archivo (AES)**: Cifra un archivo utilizando el algoritmo de cifrado simétrico AES. La clave de cifrado se genera aleatoriamente y se guarda en un archivo separado.
- **Descifrar Archivo (AES)**: Descifra un archivo cifrado previamente con AES. Requiere la clave de cifrado utilizada para el cifrado.

### Cifrado Asimétrico (RSA)

- **Generar Claves RSA**: Genera un par de claves RSA (clave pública y clave privada) y las guarda en archivos `.pem`.
- **Cifrar Archivo (RSA)**: Cifra un archivo utilizando la clave pública RSA. El archivo cifrado se guarda con la extensión `.enc`.
- **Descifrar Archivo (RSA)**: Descifra un archivo cifrado previamente con RSA. Requiere la clave privada RSA utilizada para el descifrado.

### Firma Digital

- **Firmar Archivo**: Firma un archivo utilizando la clave privada RSA. La firma se guarda en un archivo con la extensión `.sig`.
- **Verificar Firma**: Verifica la firma de un archivo utilizando la clave pública RSA. Confirma si la firma es válida para el archivo dado.

## Requisitos

- Python 3.x
- Bibliotecas:
  - `tkinter`
  - `cryptography`
  - `pycryptodome`

Puedes instalar las bibliotecas requeridas usando pip:

```bash
pip install cryptography pycryptodome
