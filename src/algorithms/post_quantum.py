import os
import time
import hashlib
import secrets
import numpy as np
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class LatticeBasedKEM:
    """
    Simplified Learning With Errors (LWE) based Key Encapsulation Mechanism.
    Demonstrates the core mathematical principles behind CRYSTALS-Kyber.
    For research and educational purposes.
    """

    def __init__(self, n=256, q=3329, security_level=128):
        self.n = n
        self.q = q
        self.security_level = security_level

    def _generate_matrix(self, seed=None):
        if seed:
            np.random.seed(seed)
        return np.random.randint(0, self.q, (self.n, self.n))

    def _sample_error(self, size):
        return np.random.randint(-3, 4, size)

    def keygen(self):
        A = self._generate_matrix()
        s = self._sample_error(self.n)
        e = self._sample_error(self.n)
        b = (A @ s + e) % self.q
        public_key = (A, b)
        private_key = s
        return public_key, private_key

    def encapsulate(self, public_key):
        A, b = public_key
        r = self._sample_error(self.n)
        e1 = self._sample_error(self.n)
        e2 = self._sample_error(1)[0]
        u = (A.T @ r + e1) % self.q
        shared_secret = secrets.token_bytes(32)
        m = int.from_bytes(
            hashlib.sha256(shared_secret).digest()[:4], 'big'
        ) % self.q
        v = (b @ r + e2 + m) % self.q
        ciphertext = (u, v)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext, private_key):
        u, v = ciphertext
        s = private_key
        m_recovered = (v - s @ u) % self.q
        return m_recovered


class HashBasedSignature:
    """
    Hash-based signature scheme inspired by XMSS/SPHINCS+.
    Uses SHA-256 chains for quantum-resistant signatures.
    """

    def __init__(self, chain_length=16):
        self.chain_length = chain_length

    def _hash_chain(self, value, steps):
        result = value
        for _ in range(steps):
            result = hashlib.sha256(result).digest()
        return result

    def keygen(self):
        private_key = secrets.token_bytes(32)
        public_key = self._hash_chain(private_key, self.chain_length)
        return public_key, private_key

    def sign(self, message, private_key):
        msg_hash = hashlib.sha256(message.encode()).digest()
        steps = int.from_bytes(msg_hash[:1], 'big') % self.chain_length
        signature = self._hash_chain(private_key, steps)
        return signature, steps

    def verify(self, message, signature, steps, public_key):
        remaining = self.chain_length - steps
        recovered = self._hash_chain(signature, remaining)
        return recovered == public_key


class ClassicalRSA:
    """RSA-2048 for benchmark comparison against post-quantum schemes."""

    def __init__(self, key_size=2048):
        self.key_size = key_size

    def keygen(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return public_key, private_key

    def encrypt(self, message, public_key):
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, ciphertext, private_key):
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
