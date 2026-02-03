/**
 * @quxtech/pqc-crypto - VoIP Module Tests
 * Tests for PQC-secured VoIP communications
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as voip from '../src/core/voip.js';

describe('VoIP Module', () => {
  // Cleanup after each test
  afterEach(() => {
    // Terminate any active calls
    const activeIds = voip.getActiveCallIds();
    for (const id of activeIds) {
      voip.terminateCall(id);
    }
  });

  describe('generateKeyPair', () => {
    it('should generate VoIP key pair at security level 5', () => {
      const keys = voip.generateKeyPair('5');

      expect(keys.kem.publicKey).toBeDefined();
      expect(keys.kem.secretKey).toBeDefined();
      expect(keys.dsa.publicKey).toBeDefined();
      expect(keys.dsa.secretKey).toBeDefined();
      expect(keys.securityLevel).toBe('5');
    });

    it('should generate VoIP key pair at security level 3', () => {
      const keys = voip.generateKeyPair('3');

      expect(keys.kem.publicKey).toBeDefined();
      expect(keys.dsa.publicKey).toBeDefined();
      expect(keys.securityLevel).toBe('3');
    });

    it('should generate different keys each time', () => {
      const keys1 = voip.generateKeyPair('5');
      const keys2 = voip.generateKeyPair('5');

      expect(keys1.kem.publicKey).not.toBe(keys2.kem.publicKey);
      expect(keys1.dsa.publicKey).not.toBe(keys2.dsa.publicKey);
    });
  });

  describe('generateCallId', () => {
    it('should generate 32-character hex call ID', () => {
      const callId = voip.generateCallId();

      expect(callId.length).toBe(32);
      expect(callId).toMatch(/^[0-9a-f]+$/i);
    });

    it('should generate unique call IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(voip.generateCallId());
      }
      expect(ids.size).toBe(100);
    });
  });

  describe('generateSSRC', () => {
    it('should generate 32-bit SSRC value', () => {
      const ssrc = voip.generateSSRC();

      expect(typeof ssrc).toBe('number');
      expect(ssrc).toBeGreaterThanOrEqual(0);
      expect(ssrc).toBeLessThanOrEqual(0xFFFFFFFF);
    });
  });

  describe('Call Establishment', () => {
    it('should create valid call request', () => {
      const callerKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys, 'OPUS');

      expect(request.callId).toBeDefined();
      expect(request.callerKemPublicKey).toBe(callerKeys.kem.publicKey);
      expect(request.callerDsaPublicKey).toBe(callerKeys.dsa.publicKey);
      expect(request.timestamp).toBeDefined();
      expect(request.signature).toBeDefined();
      expect(request.codec).toBe('OPUS');
    });

    it('should verify valid call request', () => {
      const callerKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);

      const isValid = voip.verifyCallRequest(request, '5');
      expect(isValid).toBe(true);
    });

    it('should reject tampered call request', () => {
      const callerKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);

      // Tamper with the request
      request.timestamp = Date.now() + 1000;

      const isValid = voip.verifyCallRequest(request, '5');
      expect(isValid).toBe(false);
    });

    it('should complete full call establishment flow', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');

      // Caller creates request
      const request = voip.createCallRequest(callerKeys, 'OPUS');

      // Callee accepts call
      const { response, session: calleeSession } = voip.acceptCall(request, calleeKeys);

      expect(calleeSession.callId).toBe(request.callId);
      expect(calleeSession.role).toBe('callee');
      expect(calleeSession.state).toBe('connected');
      expect(calleeSession.srtpKeys).toBeDefined();

      // Caller completes call
      const callerSession = voip.completeCall(request, response, callerKeys);

      expect(callerSession.callId).toBe(request.callId);
      expect(callerSession.role).toBe('caller');
      expect(callerSession.state).toBe('connected');

      // Both should have same shared secret
      expect(callerSession.sharedSecret).toBe(calleeSession.sharedSecret);
    });

    it('should reject call with invalid signature on accept', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);

      // Tamper with signature
      const sigChars = request.signature.split('');
      for (let i = 0; i < 10; i++) {
        sigChars[i] = sigChars[i] === 'a' ? 'b' : 'a';
      }
      request.signature = sigChars.join('');

      expect(() => {
        voip.acceptCall(request, calleeKeys);
      }).toThrow('Invalid call request signature');
    });

    it('should reject response with invalid signature on complete', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');

      const request = voip.createCallRequest(callerKeys);
      const { response } = voip.acceptCall(request, calleeKeys);

      // Tamper with response signature
      const sigChars = response.signature.split('');
      for (let i = 0; i < 10; i++) {
        sigChars[i] = sigChars[i] === 'a' ? 'b' : 'a';
      }
      response.signature = sigChars.join('');

      expect(() => {
        voip.completeCall(request, response, callerKeys);
      }).toThrow('Invalid call response signature');
    });
  });

  describe('SRTP Key Derivation', () => {
    it('should derive SRTP keys from shared secret', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');

      const request = voip.createCallRequest(callerKeys);
      const { session: calleeSession } = voip.acceptCall(request, calleeKeys);

      const srtpKeys = calleeSession.srtpKeys;

      expect(srtpKeys.encryptionKey.length).toBe(64); // 32 bytes hex
      expect(srtpKeys.authenticationKey.length).toBe(64); // 32 bytes hex
      expect(srtpKeys.saltKey.length).toBe(28); // 14 bytes hex
    });

    it('should produce consistent keys from same secret', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');

      const request = voip.createCallRequest(callerKeys);
      const { response, session: calleeSession } = voip.acceptCall(request, calleeKeys);
      const callerSession = voip.completeCall(request, response, callerKeys);

      // Both sides should have identical SRTP keys
      expect(callerSession.srtpKeys.encryptionKey).toBe(calleeSession.srtpKeys.encryptionKey);
      expect(callerSession.srtpKeys.authenticationKey).toBe(calleeSession.srtpKeys.authenticationKey);
      expect(callerSession.srtpKeys.saltKey).toBe(calleeSession.srtpKeys.saltKey);
    });
  });

  describe('Frame Encryption/Decryption', () => {
    let callId: string;

    beforeEach(() => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);
      const { response, session } = voip.acceptCall(request, calleeKeys);
      voip.completeCall(request, response, callerKeys);
      callId = session.callId;
    });

    it('should encrypt and decrypt voice frame', () => {
      const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const timestamp = Date.now();

      const encrypted = voip.encryptFrame(callId, payload, timestamp);

      expect(encrypted.sequenceNumber).toBe(1);
      expect(encrypted.timestamp).toBe(timestamp);
      expect(encrypted.nonce).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();
      expect(encrypted.authTag.length).toBe(32); // 16 bytes hex

      const decrypted = voip.decryptFrame(callId, encrypted);

      expect(decrypted.payload).toEqual(payload);
      expect(decrypted.timestamp).toBe(timestamp);
    });

    it('should increment sequence number', () => {
      const payload = new Uint8Array([1, 2, 3, 4]);

      const frame1 = voip.encryptFrame(callId, payload, 1000);
      const frame2 = voip.encryptFrame(callId, payload, 1020);
      const frame3 = voip.encryptFrame(callId, payload, 1040);

      expect(frame1.sequenceNumber).toBe(1);
      expect(frame2.sequenceNumber).toBe(2);
      expect(frame3.sequenceNumber).toBe(3);
    });

    it('should produce different ciphertexts for same payload', () => {
      const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

      const frame1 = voip.encryptFrame(callId, payload, 1000);
      const frame2 = voip.encryptFrame(callId, payload, 1020);

      expect(frame1.ciphertext).not.toBe(frame2.ciphertext);
      expect(frame1.nonce).not.toBe(frame2.nonce);
    });

    it('should reject decryption with tampered ciphertext', () => {
      const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const encrypted = voip.encryptFrame(callId, payload, 1000);

      // Tamper with ciphertext
      const chars = encrypted.ciphertext.split('');
      chars[0] = chars[0] === 'a' ? 'b' : 'a';
      encrypted.ciphertext = chars.join('');

      expect(() => {
        voip.decryptFrame(callId, encrypted);
      }).toThrow('Frame decryption failed');
    });

    it('should reject decryption with tampered auth tag', () => {
      const payload = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const encrypted = voip.encryptFrame(callId, payload, 1000);

      // Tamper with auth tag
      const chars = encrypted.authTag.split('');
      chars[0] = chars[0] === 'a' ? 'b' : 'a';
      encrypted.authTag = chars.join('');

      expect(() => {
        voip.decryptFrame(callId, encrypted);
      }).toThrow('Frame decryption failed');
    });

    it('should fail encryption without active session', () => {
      const payload = new Uint8Array([1, 2, 3, 4]);

      expect(() => {
        voip.encryptFrame('nonexistent-call-id', payload, 1000);
      }).toThrow('No active session');
    });
  });

  describe('Session Management', () => {
    it('should get active session', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);
      const { session } = voip.acceptCall(request, calleeKeys);

      const retrieved = voip.getSession(session.callId);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.callId).toBe(session.callId);
    });

    it('should return null for non-existent session', () => {
      const session = voip.getSession('nonexistent');
      expect(session).toBeNull();
    });

    it('should put call on hold and resume', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);
      const { session } = voip.acceptCall(request, calleeKeys);

      expect(session.state).toBe('connected');

      voip.holdCall(session.callId);
      const onHold = voip.getSession(session.callId);
      expect(onHold?.state).toBe('hold');

      voip.resumeCall(session.callId);
      const resumed = voip.getSession(session.callId);
      expect(resumed?.state).toBe('connected');
    });

    it('should not encrypt frames when on hold', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);
      const { session } = voip.acceptCall(request, calleeKeys);

      voip.holdCall(session.callId);

      expect(() => {
        voip.encryptFrame(session.callId, new Uint8Array([1, 2, 3, 4]), 1000);
      }).toThrow('Session not in connected state');
    });

    it('should terminate call and return stats', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);
      const { session } = voip.acceptCall(request, calleeKeys);

      // Encrypt some frames
      const payload = new Uint8Array([1, 2, 3, 4]);
      voip.encryptFrame(session.callId, payload, 1000);
      voip.encryptFrame(session.callId, payload, 1020);

      const stats = voip.terminateCall(session.callId);

      expect(stats).not.toBeNull();
      expect(stats?.callId).toBe(session.callId);
      expect(stats?.framesSent).toBe(2);
      expect(stats?.duration).toBeGreaterThanOrEqual(0);

      // Session should be removed
      expect(voip.getSession(session.callId)).toBeNull();
    });

    it('should track active call count', () => {
      expect(voip.getActiveCallCount()).toBe(0);

      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);
      const { session } = voip.acceptCall(request, calleeKeys);

      expect(voip.getActiveCallCount()).toBe(1);

      voip.terminateCall(session.callId);

      expect(voip.getActiveCallCount()).toBe(0);
    });

    it('should list active call IDs', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');

      const request1 = voip.createCallRequest(callerKeys);
      const { session: session1 } = voip.acceptCall(request1, calleeKeys);

      const request2 = voip.createCallRequest(callerKeys);
      const { session: session2 } = voip.acceptCall(request2, calleeKeys);

      const ids = voip.getActiveCallIds();

      expect(ids).toContain(session1.callId);
      expect(ids).toContain(session2.callId);
      expect(ids.length).toBe(2);
    });
  });

  describe('Statistics', () => {
    it('should track frame statistics', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);
      const { response, session: calleeSession } = voip.acceptCall(request, calleeKeys);
      voip.completeCall(request, response, callerKeys);

      const payload = new Uint8Array(100);

      // Encrypt on callee side
      const frame1 = voip.encryptFrame(calleeSession.callId, payload, 1000);
      const frame2 = voip.encryptFrame(calleeSession.callId, payload, 1020);

      // Decrypt on caller side (same call ID in test since shared storage)
      voip.decryptFrame(calleeSession.callId, frame1);

      const stats = voip.getSessionStats(calleeSession.callId);

      expect(stats?.framesSent).toBe(2);
      expect(stats?.framesReceived).toBe(1);
      expect(stats?.bytesEncrypted).toBe(200);
      expect(stats?.bytesDecrypted).toBe(100);
    });

    it('should report packet loss', () => {
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');
      const request = voip.createCallRequest(callerKeys);
      const { session } = voip.acceptCall(request, calleeKeys);

      voip.reportPacketLoss(session.callId, 5);

      const stats = voip.getSessionStats(session.callId);
      expect(stats?.packetsLost).toBe(5);
    });
  });

  describe('Utilities', () => {
    it('should estimate bandwidth for OPUS', () => {
      const bandwidth = voip.estimateBandwidth('OPUS', 960, 48000);

      // OPUS ~32kbps + overhead
      expect(bandwidth).toBeGreaterThan(4000);
      expect(bandwidth).toBeLessThan(10000);
    });

    it('should estimate higher bandwidth for G.711', () => {
      const opusBandwidth = voip.estimateBandwidth('OPUS');
      const g711Bandwidth = voip.estimateBandwidth('G711');

      expect(g711Bandwidth).toBeGreaterThan(opusBandwidth);
    });

    it('should return algorithm info', () => {
      const info = voip.getAlgorithmInfo('5');

      expect(info.kem).toBe('ML-KEM-1024');
      expect(info.dsa).toBe('ML-DSA-87');
      expect(info.symmetric).toBe('AES-256-GCM');
      expect(info.keyExchangeSize).toBe(1568);
    });

    it('should return level 3 algorithm info', () => {
      const info = voip.getAlgorithmInfo('3');

      expect(info.kem).toBe('ML-KEM-768');
      expect(info.dsa).toBe('ML-DSA-65');
    });
  });

  describe('End-to-End Secure Call', () => {
    it('should perform complete secure VoIP call simulation', () => {
      // Generate keys for caller and callee
      const callerKeys = voip.generateKeyPair('5');
      const calleeKeys = voip.generateKeyPair('5');

      // 1. Caller initiates call
      const request = voip.createCallRequest(callerKeys, 'OPUS', {
        callerName: 'Alice'
      });

      // 2. Callee verifies and accepts
      expect(voip.verifyCallRequest(request, '5')).toBe(true);
      const { response, session: calleeSession } = voip.acceptCall(request, calleeKeys);

      // 3. Caller completes call establishment
      const callerSession = voip.completeCall(request, response, callerKeys);

      // 4. Verify both have matching keys
      expect(callerSession.sharedSecret).toBe(calleeSession.sharedSecret);
      expect(callerSession.srtpKeys.encryptionKey).toBe(calleeSession.srtpKeys.encryptionKey);

      // 5. Simulate voice exchange
      const voiceData = new Uint8Array([
        0x48, 0x65, 0x6c, 0x6c, 0x6f, // "Hello" in bytes
      ]);

      // Caller sends to callee
      const encryptedFrame = voip.encryptFrame(
        callerSession.callId,
        voiceData,
        Date.now()
      );

      // Callee decrypts
      const decryptedFrame = voip.decryptFrame(
        calleeSession.callId,
        encryptedFrame
      );

      expect(decryptedFrame.payload).toEqual(voiceData);

      // 6. Terminate call
      const callerStats = voip.terminateCall(callerSession.callId);

      expect(callerStats?.framesSent).toBeGreaterThanOrEqual(1);
      expect(callerStats?.framesReceived).toBeGreaterThanOrEqual(1);
    });

    it('should work with security level 3', () => {
      const callerKeys = voip.generateKeyPair('3');
      const calleeKeys = voip.generateKeyPair('3');

      const request = voip.createCallRequest(callerKeys, 'G711');
      const { response, session: calleeSession } = voip.acceptCall(request, calleeKeys);
      const callerSession = voip.completeCall(request, response, callerKeys);

      expect(callerSession.sharedSecret).toBe(calleeSession.sharedSecret);

      const voiceData = new Uint8Array(160); // G.711 frame
      const encrypted = voip.encryptFrame(callerSession.callId, voiceData, 1000);
      const decrypted = voip.decryptFrame(calleeSession.callId, encrypted);

      expect(decrypted.payload).toEqual(voiceData);
    });
  });
});
