from qiskit import QuantumCircuit, execute, Aer
from numpy.random import randint
import numpy as np
import rsa
import hashlib
import ecdsa
import time

class R8EDSA:
    def __init__(self, message_str: str, rsa_key_size: int, sample_size: int):
        self.message_str = message_str
        self.rsa_key_size = rsa_key_size
        self.sample_size = sample_size
        self.public_key, self.private_key = rsa.newkeys(rsa_key_size)

    def prepare_message(self):
        binary_message = bytes(''.join(format(i, '08b') for i in self.message_str.encode('utf-8')), 'utf-8')
        return ''.join(format(i, '08b') for i in binary_message)

    def encryption_process(self, bits, bases, measurement_bases):
        quantum_message = self.encode_message(bits, bases)
        results = self.measure_message(quantum_message, measurement_bases)
        key = self.remove_garbage(bases, measurement_bases, bits)
        results_key = self.remove_garbage(bases, measurement_bases, results)
        bit_selection = randint(len(bits), size=self.sample_size)
        sample = self.sample_bits(key, bit_selection)
        results_sample = self.sample_bits(results_key, bit_selection)
        self.check_eavesdropping(sample, results_sample)
        return key

    def message_conversion_and_encryption(self, key):
        binary_decrypted_message = ''.join(str(i) for i in key)
        bytes_decrypted_message = int(binary_decrypted_message, 2).to_bytes((int(binary_decrypted_message, 2).bit_length() + 7) // 8, 'big')
        hex_decrypted_message = bytes_decrypted_message.hex()
        return self.encrypt(hex_decrypted_message.encode('utf-8'), self.public_key)

    def decryption_and_signature(self, encrypted_message):
        decrypted_message = self.decrypt(encrypted_message, self.private_key)
        hashed_decrypted_message = hashlib.sha256(decrypted_message).digest()[:32]
        self.generate_signature(hashed_decrypted_message)

    def execute_r8edsa(self):
        start_time = time.time()
        binary_encrypted_message = self.prepare_message()
        n = len(binary_encrypted_message)
        bits = self.generate_bits(binary_encrypted_message)
        bases = randint(2, size=n)
        measurement_bases = randint(2, size=n)
        key = self.encryption_process(bits, bases, measurement_bases)
        encrypted_message = self.message_conversion_and_encryption(key)
        self.decryption_and_signature(encrypted_message)
        end_time = time.time()
        print(f"Algoritmul a rulat în {end_time - start_time} secunde.")

    def generate_bits(self, message):
        return np.array(list(map(int, list(message))))

    def encode_message(self, bits, bases):
        message = []
        for i in range(len(bits)):
            qc = QuantumCircuit(1,1)
            if bases[i] == 0:
                if bits[i] == 1:
                    qc.x(0)
            else: 
                if bits[i] == 0:
                    qc.h(0)
                else:
                    qc.x(0)
                    qc.h(0)
            qc.barrier()
            message.append(qc)
        return message

    def measure_message(self, message, bases):
        backend = Aer.get_backend('aer_simulator')
        measurements = []
        for q in range(len(bases)):
            if bases[q] == 0:
                message[q].measure(0,0)
            if bases[q] == 1:
                message[q].h(0)
                message[q].measure(0,0)
            result = execute(message[q], backend, shots=1, memory=True).result()
            measured_bit = int(result.get_memory()[0])
            measurements.append(measured_bit)
        return measurements

    def remove_garbage(self, a_bases, b_bases, bits):
        return [bits[q] for q in range(len(a_bases)) if a_bases[q] == b_bases[q]]

    def sample_bits(self, bits, selection):
        return [bits.pop(np.mod(i, len(bits))) for i in selection]

    def check_eavesdropping(self, sample, results_sample):
        if sample != results_sample:
            print("Eavesdropping detected!")
        else:
            print("No eavesdropping detected.")

    def encrypt(self, message, public_key):
        return rsa.encrypt(message, public_key)

    def decrypt(self, message, private_key):
        return rsa.decrypt(message, private_key)

    def generate_signature(self, hashed_decrypted_message):
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        signature = sk.sign(hashed_decrypted_message)
        vk = sk.get_verifying_key()
        try:
            vk.verify(signature, hashed_decrypted_message)
            print("The signature is valid.")
        except:
            print("The signature is not valid.")