/**
 * @quxtech/pqc-crypto - Post-Quantum Cryptography Library
 * ============================================================================
 * A modular post-quantum cryptography library implementing:
 * - NIST FIPS 203: ML-KEM (CRYSTALS-Kyber) for key encapsulation
 * - NIST FIPS 204: ML-DSA (CRYSTALS-Dilithium) for digital signatures
 * - NIST FIPS 202: SHA-3 for hashing
 * - AES-256-GCM for symmetric encryption
 *
 * Security Levels:
 * - Level 3: ML-KEM-768, ML-DSA-65 (~AES-192 equivalent)
 * - Level 5: ML-KEM-1024, ML-DSA-87 (~AES-256 equivalent)
 *
 * @example
 * ```typescript
 * import { kem, dsa, symmetric, keys, session, hash } from '@quxtech/pqc-crypto';
 *
 * // Generate key pairs
 * const kemKeys = kem.generateKeyPair('5');
 * const dsaKeys = dsa.generateKeyPair('5');
 *
 * // Encapsulate shared secret
 * const { ciphertext, sharedSecret } = kem.encapsulate(recipientPublicKey);
 *
 * // Sign data
 * const signature = dsa.sign(data, dsaKeys.secretKey);
 *
 * // Encrypt with shared secret
 * const encrypted = symmetric.encryptWithSecret(data, sharedSecret);
 * ```
 *
 * @packageDocumentation
 */

// Core modules
export * as kem from './core/kem.js';
export * as dsa from './core/dsa.js';
export * as symmetric from './core/symmetric.js';
export * as keys from './core/keys.js';
export * as session from './core/session.js';
export * as voip from './core/voip.js';

// Utility modules
export * as hash from './utils/hash.js';

// Types
export type {
  SecurityLevel,
  KeyPair,
  HexKeyPair,
  KemKeyPair,
  DsaKeyPair,
  ServerKeys,
  PublicKeyExport,
  EncryptedKeyStorage,
  KeyMetadata,
  StoredKeyData,
  EncapsulationResult,
  EncryptedData,
  EncryptOptions,
  SessionData,
  SessionResponse,
  SessionStore,
  AlgorithmInfo,
  PQCConfig,
  SignedData,
  VerificationResult,
  // VoIP types
  VoIPRole,
  VoIPCodec,
  VoIPCallState,
  VoIPKeyPair,
  VoIPCallRequest,
  VoIPCallResponse,
  VoIPSession,
  VoIPSRTPKeys,
  VoIPEncryptedFrame,
  VoIPDecryptedFrame,
  VoIPSessionStats,
  VoIPConfig,
} from './types.js';

// Re-export common functions at top level for convenience
import * as kemModule from './core/kem.js';
import * as dsaModule from './core/dsa.js';
import * as symmetricModule from './core/symmetric.js';
import * as keysModule from './core/keys.js';
import * as sessionModule from './core/session.js';
import * as voipModule from './core/voip.js';
import * as hashModule from './utils/hash.js';
import type { SecurityLevel, AlgorithmInfo } from './types.js';

/**
 * Generate a complete key set (KEM + DSA)
 * @param securityLevel - NIST security level ('3' or '5')
 * @returns Object with KEM and DSA key pairs
 */
export function generateKeyPairs(securityLevel: SecurityLevel = '5') {
  return {
    kem: kemModule.generateKeyPairHex(securityLevel),
    dsa: dsaModule.generateKeyPairHex(securityLevel),
    securityLevel,
    algorithm: {
      kem: kemModule.getAlgorithmName(securityLevel),
      dsa: dsaModule.getAlgorithmName(securityLevel),
    },
  };
}

/**
 * Quick encapsulation with automatic key derivation
 * @param recipientKemPublicKey - Recipient's KEM public key
 * @param securityLevel - Security level
 * @returns Object with ciphertext and derived encryption key
 */
export function quickEncapsulate(
  recipientKemPublicKey: string,
  securityLevel: SecurityLevel = '5'
) {
  const { ciphertext, sharedSecret } = kemModule.encapsulate(recipientKemPublicKey, securityLevel);
  const encryptionKey = symmetricModule.deriveKeyHex(sharedSecret);

  return {
    ciphertext,
    encryptionKey,
    sharedSecret,
  };
}

/**
 * Quick decapsulation with automatic key derivation
 * @param ciphertext - Encapsulated ciphertext
 * @param kemSecretKey - KEM secret key
 * @param securityLevel - Security level
 * @returns Derived encryption key
 */
export function quickDecapsulate(
  ciphertext: string,
  kemSecretKey: string,
  securityLevel: SecurityLevel = '5'
) {
  const sharedSecret = kemModule.decapsulate(ciphertext, kemSecretKey, securityLevel);
  const encryptionKey = symmetricModule.deriveKeyHex(sharedSecret);

  return {
    encryptionKey,
    sharedSecret,
  };
}

/**
 * Encrypt and sign data in one operation
 * @param data - Data to encrypt
 * @param recipientKemPublicKey - Recipient's KEM public key
 * @param senderDsaSecretKey - Sender's DSA secret key
 * @param securityLevel - Security level
 * @returns Encrypted data with signature and ciphertext
 */
export function encryptAndSign(
  data: string | object,
  recipientKemPublicKey: string,
  senderDsaSecretKey: string,
  securityLevel: SecurityLevel = '5'
) {
  // Encapsulate
  const { ciphertext: kemCiphertext, sharedSecret } = kemModule.encapsulate(
    recipientKemPublicKey,
    securityLevel
  );

  // Encrypt
  const encrypted = symmetricModule.encryptWithSecret(data, sharedSecret);

  // Sign
  const signatureData = `${encrypted.nonce}:${encrypted.ciphertext}:${kemCiphertext}`;
  const signature = dsaModule.sign(signatureData, senderDsaSecretKey, securityLevel);

  return {
    kemCiphertext,
    encryptedData: encrypted,
    signature,
    timestamp: Date.now(),
  };
}

/**
 * Verify and decrypt data in one operation
 * @param payload - Encrypted payload from encryptAndSign
 * @param senderDsaPublicKey - Sender's DSA public key
 * @param recipientKemSecretKey - Recipient's KEM secret key
 * @param securityLevel - Security level
 * @returns Decrypted data or throws if verification fails
 */
export function verifyAndDecrypt(
  payload: {
    kemCiphertext: string;
    encryptedData: { nonce: string; ciphertext: string };
    signature: string;
  },
  senderDsaPublicKey: string,
  recipientKemSecretKey: string,
  securityLevel: SecurityLevel = '5'
): string {
  // Verify signature
  const signatureData = `${payload.encryptedData.nonce}:${payload.encryptedData.ciphertext}:${payload.kemCiphertext}`;
  const valid = dsaModule.verify(signatureData, payload.signature, senderDsaPublicKey, securityLevel);

  if (!valid) {
    throw new Error('Signature verification failed');
  }

  // Decapsulate
  const sharedSecret = kemModule.decapsulate(
    payload.kemCiphertext,
    recipientKemSecretKey,
    securityLevel
  );

  // Decrypt
  return symmetricModule.decryptWithSecret(payload.encryptedData, sharedSecret);
}

/**
 * Get algorithm information for a security level
 * @param securityLevel - NIST security level
 * @returns Algorithm info object
 */
export function getAlgorithmInfo(securityLevel: SecurityLevel = '5'): AlgorithmInfo {
  return {
    kem: kemModule.getAlgorithmName(securityLevel) as 'ML-KEM-768' | 'ML-KEM-1024',
    dsa: dsaModule.getAlgorithmName(securityLevel) as 'ML-DSA-65' | 'ML-DSA-87',
    symmetric: 'AES-256-GCM',
    hash: 'SHA3-256/512',
    securityLevel,
    nistFips: ['FIPS 203', 'FIPS 204', 'FIPS 202'],
  };
}

/**
 * Compute content hash (SHA3-256)
 * @param data - Data to hash
 * @returns Hash as hex string
 */
export function computeHash(data: string | Uint8Array): string {
  return hashModule.sha3256(data);
}

/**
 * Default export with all modules
 */
export default {
  kem: kemModule.default,
  dsa: dsaModule.default,
  symmetric: symmetricModule.default,
  keys: keysModule.default,
  session: sessionModule.default,
  voip: voipModule.default,
  hash: hashModule.default,
  generateKeyPairs,
  quickEncapsulate,
  quickDecapsulate,
  encryptAndSign,
  verifyAndDecrypt,
  getAlgorithmInfo,
  computeHash,
};
