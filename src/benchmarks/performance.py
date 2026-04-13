import time
import statistics
from src.algorithms.post_quantum import (
    LatticeBasedKEM, HashBasedSignature, ClassicalRSA
)


def benchmark(name, func, iterations=10):
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        times.append(time.perf_counter() - start)
    avg = statistics.mean(times) * 1000
    std = statistics.stdev(times) * 1000
    print(f"{name:<40} avg: {avg:8.2f}ms  std: {std:6.2f}ms")
    return avg


def run_all():
    print("=" * 70)
    print("Quantum-Resistant vs Classical Cryptography Benchmark")
    print("=" * 70)

    kem = LatticeBasedKEM()
    pub, priv = kem.keygen()
    ct, ss = kem.encapsulate(pub)

    print("\n[LWE-based KEM]")
    benchmark("Key Generation", lambda: kem.keygen())
    benchmark("Encapsulation", lambda: kem.encapsulate(pub))
    benchmark("Decapsulation", lambda: kem.decapsulate(ct, priv))

    hbs = HashBasedSignature()
    pub_h, priv_h = hbs.keygen()
    msg = "Merit Network darknet telescope threat signature"

    print("\n[Hash-Based Signatures]")
    benchmark("Key Generation", lambda: hbs.keygen())
    benchmark("Sign", lambda: hbs.sign(msg, priv_h))

    rsa = ClassicalRSA()
    pub_r, priv_r = rsa.keygen()
    plaintext = b"quantum threat intelligence payload"

    print("\n[Classical RSA-2048 (baseline)]")
    benchmark("Key Generation", lambda: rsa.keygen())
    ciphertext = rsa.encrypt(plaintext, pub_r)
    benchmark("Decrypt", lambda: rsa.decrypt(ciphertext, priv_r))

    print("\n" + "=" * 70)
    print("Post-quantum schemes ready for quantum-era threat environments.")
    print("=" * 70)


if __name__ == "__main__":
    run_all()
