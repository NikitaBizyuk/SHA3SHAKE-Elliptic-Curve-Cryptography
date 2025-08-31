Part 1 - SHA3/SHAKE:

SHA-3 hash functions (224, 256, 384, 512-bit outputs)
SHAKE extendable output functions (128, 256 security levels)
Symmetric encryption with SHAKE-128 keystreams
MAC authentication using SHAKE algorithms

Part 2 - Elliptic Curve Cryptography:

NUMS-256 Edwards curve implementation
ECIES public-key encryption with authenticated encryption
Schnorr digital signatures for authentication
Deterministic key generation from passphrases
---------------------------------------------------------------
Compilation
bashjavac *.java
Basic Usage
bash# Hash a file
java Main hash document.txt

# Generate key pair
java Main genkey mypassword alice.pub

# Encrypt file
java Main eciesenc document.txt encrypted.dat alice.pub

# Sign document
java Main sign document.txt signature.sig mypassword

# Verify signature
java Main verify document.txt signature.sig alice.pub
