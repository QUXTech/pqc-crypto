# @quxtech/pqc-crypto

[![CI](https://github.com/QUXTech/pqc-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/QUXTech/pqc-crypto/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@quxtech/pqc-crypto.svg)](https://www.npmjs.com/package/@quxtech/pqc-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

A modular post-quantum cryptography library implementing NIST-standardized algorithms for quantum-safe encryption and digital signatures.

## Features

- **ML-KEM (CRYSTALS-Kyber)** - Post-quantum key encapsulation (NIST FIPS 203)
- **ML-DSA (CRYSTALS-Dilithium)** - Post-quantum digital signatures (NIST FIPS 204)
- **AES-256-GCM** - Symmetric encryption with PQC-derived keys
- **SHA3-256/512** - Secure hashing (NIST FIPS 202)
- **Key Management** - Encrypted key storage with passphrase protection
- **Session Management** - Secure session handling with pluggable stores

## Security Levels

| Level | KEM Algorithm | DSA Algorithm | Equivalent Strength |
|-------|---------------|---------------|---------------------|
| 3 | ML-KEM-768 | ML-DSA-65 | ~AES-192 |
| 5 | ML-KEM-1024 | ML-DSA-87 | ~AES-256 |

## Installation

```bash
npm install @quxtech/pqc-crypto
```

## Quick Start

```typescript
import { kem, dsa, symmetric, generateKeyPairs } from '@quxtech/pqc-crypto';

// Generate key pairs (Security Level 5)
const alice = generateKeyPairs('5');
const bob = generateKeyPairs('5');

// Alice encapsulates a shared secret to Bob
const { ciphertext, sharedSecret } = kem.encapsulate(bob.kem.publicKey);

// Bob decapsulates to get the same shared secret
const bobSecret = kem.decapsulate(ciphertext, bob.kem.secretKey);

// Encrypt a message using the shared secret
const encrypted = symmetric.encryptWithSecret('Hello, quantum-safe world!', sharedSecret);

// Decrypt
const decrypted = symmetric.decryptWithSecret(encrypted, bobSecret);
console.log(decrypted); // 'Hello, quantum-safe world!'

// Sign and verify
const signature = dsa.sign('Important message', alice.dsa.secretKey);
const isValid = dsa.verify('Important message', signature, alice.dsa.publicKey);
console.log(isValid); // true
```

## Modules

### Key Encapsulation (KEM)

```typescript
import { kem } from '@quxtech/pqc-crypto';

// Generate key pair
const keyPair = kem.generateKeyPair('5');
const hexKeyPair = kem.generateKeyPairHex('5');

// Encapsulate
const { ciphertext, sharedSecret } = kem.encapsulate(recipientPublicKey, '5');

// Decapsulate
const secret = kem.decapsulate(ciphertext, secretKey, '5');
```

### Digital Signatures (DSA)

```typescript
import { dsa } from '@quxtech/pqc-crypto';

// Generate key pair
const keyPair = dsa.generateKeyPair('5');

// Sign
const signature = dsa.sign(message, keyPair.secretKey, '5');

// Verify
const isValid = dsa.verify(message, signature, keyPair.publicKey, '5');

// Sign with timestamp (replay protection)
const { signature, timestamp } = dsa.signWithTimestamp(data, secretKey);

// Verify with timestamp (5-minute window)
const result = dsa.verifyWithTimestamp(data, signature, timestamp, publicKey);
```

### Symmetric Encryption

```typescript
import { symmetric } from '@quxtech/pqc-crypto';

// Derive key from shared secret
const key = symmetric.deriveKey(sharedSecret, 'my-context');

// Encrypt
const encrypted = symmetric.encrypt(data, key);

// Decrypt
const decrypted = symmetric.decryptToString(encrypted, key);

// Or use shared secret directly
const encrypted = symmetric.encryptWithSecret(data, sharedSecret);
const decrypted = symmetric.decryptWithSecret(encrypted, sharedSecret);
```

### Key Management

```typescript
import { keys } from '@quxtech/pqc-crypto';

// Generate server keys
const serverKeys = keys.generateServerKeys('5');

// Serialize to encrypted storage
const encrypted = keys.serializeKeys(serverKeys, 'my-passphrase');

// Save to file
await fs.writeFile('keys.enc', JSON.stringify(encrypted));

// Load from encrypted storage
const loaded = keys.deserializeKeys(encrypted, 'my-passphrase');

// Get public keys for distribution
const publicKeys = keys.getPublicKeys();
```

### Session Management

```typescript
import { session } from '@quxtech/pqc-crypto';

// Configure (optional)
session.configure({ ttlMs: 3600000 }); // 1 hour TTL

// Create session
const response = await session.createSession(sessionId, clientKemPublicKey);

// Get session secret
const secret = await session.getSessionSecret(sessionId);

// Destroy session
await session.destroySession(sessionId);

// Use Redis store
import { createClient } from 'redis';
const redis = createClient();
session.configure({ store: session.createRedisStore(redis) });
```

### Hashing

```typescript
import { hash } from '@quxtech/pqc-crypto';

// SHA3-256
const h256 = hash.sha3256('data');

// SHA3-512
const h512 = hash.sha3512('data');

// Keccak-256 (Ethereum-style)
const kec = hash.keccak256('data');

// Hash object with sorted keys
const objHash = hash.hashObject({ b: 2, a: 1 });

// Short fingerprint
const fp = hash.fingerprint('data');
```

## High-Level API

```typescript
import { encryptAndSign, verifyAndDecrypt } from '@quxtech/pqc-crypto';

// Encrypt and sign in one operation
const payload = encryptAndSign(
  { message: 'Secret data' },
  recipientKemPublicKey,
  senderDsaSecretKey
);

// Verify and decrypt
const data = verifyAndDecrypt(
  payload,
  senderDsaPublicKey,
  recipientKemSecretKey
);
```

## TypeScript Support

Full TypeScript support with exported types:

```typescript
import type {
  SecurityLevel,
  KeyPair,
  EncryptedData,
  SessionStore,
  AlgorithmInfo,
} from '@quxtech/pqc-crypto';
```

## Subpath Exports

Import only what you need:

```typescript
import { encapsulate, decapsulate } from '@quxtech/pqc-crypto/kem';
import { sign, verify } from '@quxtech/pqc-crypto/dsa';
import { encrypt, decrypt } from '@quxtech/pqc-crypto/symmetric';
import { sha3256 } from '@quxtech/pqc-crypto/hash';
```

## Security Considerations

- **Key Storage**: Always encrypt secret keys at rest using `keys.serializeKeys()`
- **Passphrase Strength**: Use strong, unique passphrases for key encryption
- **Session Expiration**: Configure appropriate TTL for your use case
- **Signature Timestamps**: Use `signWithTimestamp()` for replay protection
- **Security Level**: Use Level 5 for maximum security, Level 3 for better performance

## Standards Compliance

- **NIST FIPS 203** - ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **NIST FIPS 204** - ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **NIST FIPS 202** - SHA-3 (Secure Hash Algorithm 3)
- **NIST SP 800-56C Rev. 2** - Key Derivation Methods

## License

MIT

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
