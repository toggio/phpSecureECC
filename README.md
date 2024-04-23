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

## Requirements
- PHP GMP Extension
- (optional) PHP OPENSSL Extension (for encryption and decryption methods)


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

### Encrypting and Decrypting Messages (with or without Digital Signatures)

Use private key along with the other party's public key to securely encrypt messages

```php
// Encrypt a message using Alice's private key and Bob's public key
$encrypted = $eccAlice->encrypt("Secure message", $privateKeyAlice, $publicKeyBob);

// Decrypt the message using Bob's private key and Alice's public key
$decrypted = $eccBob->decrypt(encrypted, $privateKeyBob, $publicKeyAlice);
```

Optionally add a digital signature to sign and verify messages for enhanced security

```php
// Encrypt a message using Alice's private key and Bob's public key
$encrypted = $eccAlice->encrypt("Secure message", $privateKeyAlice, $publicKeyBob,true);

// Decrypt the message using Bob's private key and Alice's public key
$decrypted = $eccBob->decrypt($encrypted, $privateKeyBob, $publicKeyAlice,true);
```

Use other party's public key to encrypt message

```php
// Encrypt a message using Bob's public key
$encrypted = $eccAlice->encryptWithSingleKey("Secure message", $publicKeyBob);

// Decrypt the message using Bob's private key
$decrypted = $eccBob->decryptWithSingleKey($encrypted, $privateKeyBob);
```

With digital signature check

```php
// Encrypt a message using Bob's public key
$encrypted = $eccAlice->encryptWithSingleKey("Secure message", $publicKeyBob,true);

// Decrypt the message using Bob's private key
$decrypted = $eccBob->decryptWithSingleKey($encrypted, $privateKeyBob,true);
```

### Signing and verifying messages (Digital Signatures)

Create and verify digital signatures to validate the authenticity and integrity of messages

```php
// Sign a message with Alice's private key
$signature = $eccAlice->sign("Verify me", $privateKeyAlice);

// Verify the signature with Alice's public key
$isVerified = $eccBob->verify("Verify me", $signature, $publicKeyAlice);
echo $isVerified ? "Signature verified successfully." : "Signature verification failed.";
```

## Advanced Usage

For users seeking to utilize the full spectrum of capabilities offered by phpSecureECC, the library includes several advanced methods. Detailed explanations and usage guidelines for these methods can be found in the extensive comments within the class file itself. These comments provide insights into the nuances of the cryptographic operations and help guide the implementation of more complex functionalities.

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to fork the repository, make changes, and submit pull requests. Please open issues for any bugs or enhancements you have in mind.

## Help us

If you find this project useful and would like to support its development, consider making a donation. Any contribution is greatly appreciated!

**Bitcoin (BTC) Addresses:**
- **1LToggio**f3rNUTCemJZSsxd1qubTYoSde6  
- **3LToggio**7Xx8qMsjCFfiarV4U2ZR9iU9ob

## License
**phpSecureECC** library is licensed under the Apache License, Version 2.0. You are free to use, modify, and distribute the library in compliance with the license.

Copyright (C) 2024 Luca Soltoggio - https://www.lucasoltoggio.it/
