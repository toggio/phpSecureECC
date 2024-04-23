# phpSecureECC
A Pure PHP Elliptic Curve Cryptography Library that implements Elliptic Curve Diffie-Hellman (ECDH) and Elliptic Curve Digital Signature Algorithm (ECDSA) using the secp256k1 elliptic curve parameters.  

This library provides robust tools for secure key generation, message encryption/decryption, and digital signature verification in PHP.  

## Features
- **Key Generation**: Generate private and public keys for elliptic curve cryptography.
- **Public Key Derivation**: Derive a public key from a provided private key in hexadecimal format.
- **Public Key Compression/Decompression**: Manage public keys efficiently with built-in compression and decompression functionalities.
- **ECDH Key Exchange**: Facilitate secure key exchanges between parties and shared key derivation to encrypt subsequent communications.
- **ECDSA Signing and Verification**: Generate and verify signatures to ensure message integrity and authenticity.
- **Encryption & Decryption**: Encrypt and decrypt messages using ECDH derived keys with buit-in methods. Supports signing and verification of messages.
- **Secp256k1 Support**: Leverage the secp256k1 curve, widely used in blockchain technologies like Bitcoin.
- **Base58 Encoding/Decoding**: Encode and decode data in Base58, commonly used in cryptocurrencies for a more compact, human-readable format.
- **Pure PHP**: Single file, easy to use class with no need for external libraries.

## Usage

### Installation

To use phpSecureECC in your projects, download and include the PHP class in your project:

```php
require_once 'path/to/phpSecureECC.php';
```
### Generating Keys

Generate a new private and public key pair for secure communications:

```php
$ecc = new phpSecureECC();
$privateKey = $ecc->generatePrivateKey();
$publicKey = $ecc->derivePublicKey($privateKey);
```

### Compressing/Decompressing Keys

Compress and decompress a public key

```php
$compressedKey = $ecc->compressPublicKey($publicKey);
$decompressedKey = $ecc->decompressPublicKey($compressedKey);
```

### Deriving Shared Keys

The Elliptic Curve Diffie-Hellman (ECDH) protocol allows two parties to establish a shared secret over an insecure channel. This shared secret can then be used to encrypt subsequent communications.

```php
// Alice's side
$eccAlice = new phpSecureECC();
$privateKeyAlice = $eccAlice->generatePrivateKey();
// This public key can be shared with Bob through an insecure channel
$publicKeyAlice = $eccAlice->derivePublicKey($privateKeyAlice);

// Bob's side
$eccBob = new phpSecureECC();
$privateKeyBob = $eccBob->generatePrivateKey();
// This public key can be shared with Alice through an insecure channel
$publicKeyBob = $eccBob->derivePublicKey($privateKeyBob);

// Derive the shared key
// Alice uses her private key and Bob's public key
$sharedKeyAlice = $eccAlice->calculateSharedKey($privateKeyAlice, $publicKeyBob);

// Bob uses his private key and Alice's public key
$sharedKeyBob = $eccBob->calculateSharedKey($privateKeyBob, $publicKeyAlice);

// Both shared keys should be identical
echo $sharedKeyAlice === $sharedKeyBob ? "Shared keys match." : "Shared keys do not match.";

// This shared secret can then be used by both Alice and Bob to encrypt subsequent communications using AES or another cryptographic algorithm
```
