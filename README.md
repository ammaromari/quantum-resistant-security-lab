# Quantum-Resistant Security Lab

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Security](https://img.shields.io/badge/security-post--quantum-green.svg)

Research laboratory for post-quantum cryptographic algorithms. Implements 
and benchmarks quantum-resistant schemes against classical cryptography to 
evaluate readiness for the post-quantum threat landscape.

Built in the context of network security research at Merit Network, where 
long-term data integrity of 20+ years of darknet telescope data requires 
cryptographic schemes resilient to future quantum attacks.

## Algorithms Implemented

**Post-Quantum:**
- LWE-based Key Encapsulation Mechanism (inspired by CRYSTALS-Kyber)
- Hash-Based Signatures (inspired by XMSS/SPHINCS+)

**Classical (benchmark baseline):**
- RSA-2048 with OAEP padding

## Quick Start

git clone https://github.com/ammaromari/quantum-resistant-security-lab.git
cd quantum-resistant-security-lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m src.benchmarks.performance


## Research Context

NIST standardized post-quantum cryptographic algorithms in 2024 (CRYSTALS-Kyber, 
CRYSTALS-Dilithium, SPHINCS+). This lab provides reference implementations to 
evaluate migration paths for existing security infrastructure — particularly 
relevant for long-lived encrypted archives and network security telemetry systems.

## License

MIT
