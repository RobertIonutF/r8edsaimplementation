
# R8EDSA Quantum Encryption Algorithm

This Python module implements the R8EDSA quantum encryption algorithm. It uses the Qiskit library for quantum computations and the rsa and ecdsa libraries for classical encryption and digital signatures.

## Class Definition

The `R8EDSA` class is the main class in this module. It is initialized with a message string, an RSA key size, and a sample size.

### Methods

- `__init__(self, message_str: str, rsa_key_size: int, sample_size: int)`: Initializes the `R8EDSA` object with a message, RSA key size, and sample size. It also generates an RSA public and private key pair.

- `prepare_message(self)`: Converts the message string to binary.

- `encryption_process(self, bits, bases, measurement_bases)`: Performs encryption of the message bits using quantum circuits. Checks for eavesdropping.

- `message_conversion_and_encryption(self, key)`: Converts the key into a binary string and then encrypts it using RSA encryption.

- `decryption_and_signature(self, encrypted_message)`: Decrypts the message and generates a signature for the hashed decrypted message.

- `execute_r8edsa(self)`: Executes the entire R8EDSA process, which includes preparing the message, generating bits and bases, performing encryption, decrypting the message, and generating a signature.

## Dependencies

- Qiskit
- rsa
- ecdsa
- numpy
- hashlib
- time

## Example Usage

```python
from r8edsa import R8EDSA

message = "Hello, World!"
rsa_key_size = 2048
sample_size = 100

encryption_object = R8EDSA(message, rsa_key_size, sample_size)
encryption_object.execute_r8edsa()
```

Please note that you need to replace `from r8edsa import R8EDSA` with the correct import based on how the module is named and where it is located in your project structure.
