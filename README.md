# ![AES-Python: A Python implementation of the Advanced Encryption Standard (AES)](https://raw.githubusercontent.com/glindeb/aes-python/core-restructure/repo/AES-Python-logo.png)

<div align=center>
  <a><img src="https://img.shields.io/badge/python%20-%203.8%20%7C%C2%A03.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20-%20blue?logo=python&logoColor=white&color=247ac9"></a>
  <a><img src="https://img.shields.io/github/repo-size/glindeb/AES-python?label=size"></a>  
  <a><img src="https://img.shields.io/github/license/glindeb/AES-Python"></a>
  <a><img src="https://github.com/Glindeb/AES-Python/actions/workflows/test.yml/badge.svg"></a>
</div>

The `AES-Python` package is a Python implementation of the [Advanced Encryption Standard (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) using symmetric key cryptography. It supports two different modes of operation ([ECB, CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)) and the key lengths 128, 256, 512 bit. This project was originally created as a school project using almost only built in python libraries, but has now been updated and adapted to more heavily really on the [NumPy](https://numpy.org) and [galois](https://github.com/mhostetter/galois) packages. It has also been migrated to a more [OOP](https://en.wikipedia.org/wiki/Object-oriented_programming) focused structure. (The original school project can be seen in the [legacy](https://github.com/Glindeb/AES-Python/tree/legacy) branch.) 

> **Warning:**
> This project is not intended to be used in any other use case than experimentation and educational use. No security is guaranteed for data encrypted or decrypted using this library, and it may very well contain multiple unaddressed security vulnerabilities.

Features
---
- Implementation of the AES encryption and decryption processes.
- Support for two different modes of operation: ECB, CBC.
- Support for the three different key lengths included in the [AES standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf). (128, 192, 256 bit)
- Key expansion and round key generation.
- Encryption & decryption of individual files.
- Encryption & decryption of python string objects.

Acknowledgements
---
The `AES-Python` project relies heavily on both the [NumPy](https://numpy.org) and [galois](https://github.com/mhostetter/galois) packages in order to manage integer arrays and preform matrix operations and GF(2^8) [finite field](https://en.wikipedia.org/wiki/Finite_field) multiplication operations. This project would not have been possible without these libraries, so I would like to thank the developers of these projects.

Getting started
---
This is a short guide to help you get started.

### Installation
You can install the latest version of `AES-Python` from [PyPI](Fix this link!!!!) using pip.

```
$ python3 -m pip install AES-Python
```

### Usage
Now you can import it and use it in you projects. Below is a short example snippet of how to utilize the package.

```
from AES-Python.AES import AES

# Initialize the AES object
aes = AES(r_mode="ECB", key="your-encryption-key")

# Encrypt the data
encrypted_data = aes.enc("your-data")

# Decrypt the data
decrypted_data = aes.dec("your-encrypted-data")
```
