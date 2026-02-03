/**
 * @quxtech/pqc-crypto - Type Definitions
 * ============================================================================
 * Post-Quantum Cryptography type definitions
 * ============================================================================
 */

// =============================================================================
// SECURITY LEVELS
// =============================================================================

/**
 * NIST Security Levels
 * - Level 3: ~AES-192 equivalent (ML-KEM-768, ML-DSA-65)
 * - Level 5: ~AES-256 equivalent (ML-KEM-1024, ML-DSA-87)
 */
export type SecurityLevel = '3' | '5';

// =============================================================================
// KEY TYPES
// =============================================================================

/**
 * Generic key pair
 */
export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * Key pair with hex-encoded keys
 */
export interface HexKeyPair {
  publicKey: string;
  secretKey: string;
}

/**
 * ML-KEM (Kyber) specific key pair
 */
export interface KemKeyPair extends KeyPair {
  algorithm: 'ML-KEM-768' | 'ML-KEM-1024';
}

/**
 * ML-DSA (Dilithium) specific key pair
 */
export interface DsaKeyPair extends KeyPair {
  algorithm: 'ML-DSA-65' | 'ML-DSA-87';
}

/**
 * Server key set containing both KEM and DSA keys
 */
export interface ServerKeys {
  kem: KeyPair;
  dsa: KeyPair;
  initialized: boolean;
  generatedAt?: string;
  securityLevel: SecurityLevel;
}

/**
 * Public key export format
 */
export interface PublicKeyExport {
  kemPublicKey: string;
  dsaPublicKey: string;
  securityLevel: SecurityLevel;
  algorithm: {
    kem: string;
    dsa: string;
  };
}

// =============================================================================
// KEY STORAGE TYPES
// =============================================================================

/**
 * Encrypted key storage format
 */
export interface EncryptedKeyStorage {
  version: number;
  salt: string;
  nonce: string;
  ciphertext: string;
}

/**
 * Key metadata
 */
export interface KeyMetadata {
  generatedAt: string;
  securityLevel: SecurityLevel;
  algorithm: {
    kem: string;
    dsa: string;
  };
}

/**
 * Stored key data format (before encryption)
 */
export interface StoredKeyData {
  kem: HexKeyPair;
  dsa: HexKeyPair;
  metadata: KeyMetadata;
}

// =============================================================================
// ENCAPSULATION TYPES
// =============================================================================

/**
 * Result of KEM encapsulation
 */
export interface EncapsulationResult {
  ciphertext: string;
  sharedSecret: string;
}

// =============================================================================
// ENCRYPTION TYPES
// =============================================================================

/**
 * Encrypted data structure
 */
export interface EncryptedData {
  nonce: string;
  ciphertext: string;
}

/**
 * Encryption options
 */
export interface EncryptOptions {
  context?: string;
}

// =============================================================================
// SESSION TYPES
// =============================================================================

/**
 * Session data stored server-side
 */
export interface SessionData {
  sharedSecret: string;
  createdAt: number;
  lastUsed: number;
  metadata?: Record<string, unknown>;
}

/**
 * Session creation response
 */
export interface SessionResponse {
  sessionId: string;
  ciphertext: string;
  signature: string;
  expiresIn: number;
}

/**
 * Session store interface for custom implementations
 */
export interface SessionStore {
  get(sessionId: string): Promise<SessionData | null>;
  set(sessionId: string, data: SessionData): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
}

// =============================================================================
// ALGORITHM INFO
// =============================================================================

/**
 * Algorithm information
 */
export interface AlgorithmInfo {
  kem: 'ML-KEM-768' | 'ML-KEM-1024';
  dsa: 'ML-DSA-65' | 'ML-DSA-87';
  symmetric: 'AES-256-GCM';
  hash: 'SHA3-256/512';
  securityLevel: SecurityLevel;
  nistFips: string[];
}

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Library configuration options
 */
export interface PQCConfig {
  securityLevel?: SecurityLevel;
  sessionTtlMs?: number;
  keyStoragePath?: string;
  sessionStore?: SessionStore;
}

// =============================================================================
// SIGNATURE TYPES
// =============================================================================

/**
 * Signed data with metadata
 */
export interface SignedData {
  data: string;
  signature: string;
  timestamp: number;
  publicKeyFingerprint: string;
}

/**
 * Verification result
 */
export interface VerificationResult {
  valid: boolean;
  timestamp?: number;
  error?: string;
}

// =============================================================================
// VOIP TYPES
// =============================================================================

/**
 * VoIP participant role
 */
export type VoIPRole = 'caller' | 'callee';

/**
 * VoIP codec types (for metadata)
 */
export type VoIPCodec = 'OPUS' | 'G711' | 'G722' | 'G729' | 'PCMU' | 'PCMA';

/**
 * VoIP call state
 */
export type VoIPCallState =
  | 'initializing'
  | 'ringing'
  | 'connected'
  | 'hold'
  | 'terminated';

/**
 * VoIP key pair for a participant
 */
export interface VoIPKeyPair {
  kem: HexKeyPair;
  dsa: HexKeyPair;
  securityLevel: SecurityLevel;
}

/**
 * VoIP call initiation request (INVITE equivalent)
 */
export interface VoIPCallRequest {
  callId: string;
  callerKemPublicKey: string;
  callerDsaPublicKey: string;
  timestamp: number;
  signature: string;
  codec?: VoIPCodec;
  metadata?: Record<string, unknown>;
}

/**
 * VoIP call response (200 OK equivalent)
 */
export interface VoIPCallResponse {
  callId: string;
  ciphertext: string;
  calleeDsaPublicKey: string;
  timestamp: number;
  signature: string;
  codec?: VoIPCodec;
}

/**
 * Established VoIP session
 */
export interface VoIPSession {
  callId: string;
  role: VoIPRole;
  state: VoIPCallState;
  sharedSecret: string;
  srtpKeys: VoIPSRTPKeys;
  localDsaPublicKey: string;
  remoteDsaPublicKey: string;
  establishedAt: number;
  sequenceNumber: number;
  rolloverCounter: number;
  ssrc: number;
  codec?: VoIPCodec;
}

/**
 * SRTP-derived keys for encryption and authentication
 */
export interface VoIPSRTPKeys {
  encryptionKey: string;
  authenticationKey: string;
  saltKey: string;
}

/**
 * Encrypted voice frame (RTP-like)
 */
export interface VoIPEncryptedFrame {
  sequenceNumber: number;
  timestamp: number;
  ssrc: number;
  nonce: string;
  ciphertext: string;
  authTag: string;
}

/**
 * Decrypted voice frame
 */
export interface VoIPDecryptedFrame {
  sequenceNumber: number;
  timestamp: number;
  ssrc: number;
  payload: Uint8Array;
}

/**
 * VoIP session statistics
 */
export interface VoIPSessionStats {
  callId: string;
  duration: number;
  framesSent: number;
  framesReceived: number;
  bytesEncrypted: number;
  bytesDecrypted: number;
  packetsLost: number;
}

/**
 * VoIP configuration options
 */
export interface VoIPConfig {
  securityLevel?: SecurityLevel;
  codec?: VoIPCodec;
  frameSize?: number;
  sampleRate?: number;
  enableStats?: boolean;
}
