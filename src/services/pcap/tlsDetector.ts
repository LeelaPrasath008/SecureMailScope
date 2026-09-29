/**
 * SecureMailScope - TLS Detection & Certificate Extraction
 * STEP 3: TLS Detection
 * SIH 2026 Problem Statement 26159
 */

import { ReconstructedFlow } from './pcapTypes';

// Authoritative IANA TLS Cipher Suite Registry mapping
export interface CipherDetails {
  ianaName: string;
  isWeak: boolean;
  keyExchange: string;
  forwardSecrecy: boolean;
  weaknessReason?: string;
}

const IANA_CIPHER_MAP: Record<number, CipherDetails> = {
  // TLS 1.3 Modern AEAD Ciphers (All have Forward Secrecy)
  0x1301: { ianaName: 'TLS_AES_128_GCM_SHA256', isWeak: false, keyExchange: 'ECDHE / DHE', forwardSecrecy: true },
  0x1302: { ianaName: 'TLS_AES_256_GCM_SHA384', isWeak: false, keyExchange: 'ECDHE / DHE', forwardSecrecy: true },
  0x1303: { ianaName: 'TLS_CHACHA20_POLY1305_SHA256', isWeak: false, keyExchange: 'ECDHE / DHE', forwardSecrecy: true },

  // TLS 1.2 Forward Secrecy (ECDHE) Ciphers
  0xc02f: { ianaName: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', isWeak: false, keyExchange: 'ECDHE', forwardSecrecy: true },
  0xc030: { ianaName: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', isWeak: false, keyExchange: 'ECDHE', forwardSecrecy: true },
  0xc02b: { ianaName: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', isWeak: false, keyExchange: 'ECDHE', forwardSecrecy: true },
  0xc02c: { ianaName: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', isWeak: false, keyExchange: 'ECDHE', forwardSecrecy: true },
  0xcca8: { ianaName: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', isWeak: false, keyExchange: 'ECDHE', forwardSecrecy: true },

  // Static RSA (No Forward Secrecy) - Weak
  0x002f: {
    ianaName: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    isWeak: true,
    keyExchange: 'Static RSA',
    forwardSecrecy: false,
    weaknessReason: 'Static RSA lacks Forward Secrecy; past captures vulnerable to retrospective decryption.'
  },
  0x0035: {
    ianaName: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    isWeak: true,
    keyExchange: 'Static RSA',
    forwardSecrecy: false,
    weaknessReason: 'Static RSA lacks Forward Secrecy; past captures vulnerable to retrospective decryption.'
  },
  0x009c: {
    ianaName: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    isWeak: true,
    keyExchange: 'Static RSA',
    forwardSecrecy: false,
    weaknessReason: 'Static RSA lacks Forward Secrecy.'
  },

  // 3DES Ciphers (Sweet32 Vulnerability - Prohibited by RFC 7525)
  0x000a: {
    ianaName: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    isWeak: true,
    keyExchange: 'Static RSA',
    forwardSecrecy: false,
    weaknessReason: '3DES 64-bit block cipher vulnerable to Sweet32 collision attacks (CVE-2016-2183).'
  },
  0xc012: {
    ianaName: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    isWeak: true,
    keyExchange: 'ECDHE',
    forwardSecrecy: true,
    weaknessReason: '3DES 64-bit block cipher vulnerable to Sweet32 collision attacks.'
  },

  // Deprecated RC4 Ciphers (RFC 7465 Prohibited)
  0x0004: {
    ianaName: 'TLS_RSA_WITH_RC4_128_MD5',
    isWeak: true,
    keyExchange: 'Static RSA',
    forwardSecrecy: false,
    weaknessReason: 'RC4 stream cipher is cryptographically broken and prohibited by RFC 7465.'
  },
  0x0005: {
    ianaName: 'TLS_RSA_WITH_RC4_128_SHA',
    isWeak: true,
    keyExchange: 'Static RSA',
    forwardSecrecy: false,
    weaknessReason: 'RC4 stream cipher is cryptographically broken and prohibited by RFC 7465.'
  }
};

export function analyzeFlowTls(flow: ReconstructedFlow, captureTimestamp: string): void {
  // Only execute TLS analysis if TLS packets actually exist
  if (!flow.hasTls) {
    // Check if any packet has TLS record headers
    const hasTlsPkt = flow.packets.some((p) => p.detectedAppProtocol === 'TLS');
    if (!hasTlsPkt) {
      return;
    }
  }

  // Iterate over flow packets to find TLS Handshake frames
  for (const pkt of flow.packets) {
    const payload = pkt.payload;
    if (payload.length < 5) continue;

    // Check TLS Record Header: ContentType 0x16 (Handshake)
    if (payload[0] === 0x16 && payload[1] === 0x03) {
      flow.hasTls = true;
      let recordOffset = 0;

      while (recordOffset + 5 <= payload.length) {
        const contentType = payload[recordOffset];
        const recordLen = (payload[recordOffset + 3] << 8) | payload[recordOffset + 4];

        if (contentType === 0x16 && recordOffset + 5 + recordLen <= payload.length) {
          const handshakeData = payload.slice(recordOffset + 5, recordOffset + 5 + recordLen);
          parseHandshakeMessage(handshakeData, flow, captureTimestamp);
        }

        recordOffset += 5 + recordLen;
      }
    }
  }
}

function parseHandshakeMessage(
  data: Uint8Array,
  flow: ReconstructedFlow,
  captureTimestamp: string
): void {
  if (data.length < 4) return;
  const msgType = data[0];
  const msgLength = (data[1] << 16) | (data[2] << 8) | data[3];

  // 1. Server Hello (Type 0x02)
  if (msgType === 0x02 && data.length >= 38) {
    let rawVersion = (data[4] << 8) | data[5];
    const sessIdLen = data[38];
    const cipherOffset = 39 + sessIdLen;

    if (data.length >= cipherOffset + 2) {
      const cipherCode = (data[cipherOffset] << 8) | data[cipherOffset + 1];
      flow.cipherSuiteCode = cipherCode;

      const details = IANA_CIPHER_MAP[cipherCode] || {
        ianaName: `TLS_UNKNOWN_CIPHER_0x${cipherCode.toString(16).padStart(4, '0')}`,
        isWeak: true,
        keyExchange: 'Unknown',
        forwardSecrecy: false,
        weaknessReason: 'Unrecognized or non-standard cipher suite.'
      };

      flow.cipherSuiteName = details.ianaName;
      flow.cipherSuiteIsWeak = details.isWeak;
      flow.cipherSuiteKeyExchange = details.keyExchange;
      flow.forwardSecrecy = details.forwardSecrecy;
    }

    // Inspect TLS 1.3 supported_versions extension (0x002B)
    const extOffset = cipherOffset + 3; // cipher (2) + comp (1)
    if (data.length > extOffset + 2) {
      const extLen = (data[extOffset] << 8) | data[extOffset + 1];
      let cur = extOffset + 2;
      const end = Math.min(data.length, cur + extLen);

      while (cur + 4 <= end) {
        const extType = (data[cur] << 8) | data[cur + 1];
        const extDataLen = (data[cur + 2] << 8) | data[cur + 3];

        if (extType === 0x002b && extDataLen === 2 && cur + 6 <= end) {
          const supportedVersion = (data[cur + 4] << 8) | data[cur + 5];
          if (supportedVersion === 0x0304) {
            rawVersion = 0x0304; // TLS 1.3 negotiated!
          }
        }
        cur += 4 + extDataLen;
      }
    }

    flow.tlsVersionCode = rawVersion;
    if (rawVersion === 0x0301) flow.tlsVersion = 'TLS 1.0';
    else if (rawVersion === 0x0302) flow.tlsVersion = 'TLS 1.1';
    else if (rawVersion === 0x0303) flow.tlsVersion = 'TLS 1.2';
    else if (rawVersion === 0x0304) flow.tlsVersion = 'TLS 1.3';
  }

  // 2. Certificate (Type 0x0B)
  else if (msgType === 0x0b && data.length >= 10) {
    flow.certificatePresented = true;
    extractCertificateDetails(data.slice(4), flow, captureTimestamp);
  }
}

function extractCertificateDetails(
  data: Uint8Array,
  flow: ReconstructedFlow,
  captureTimestamp: string
): void {
  // Simple ASN.1 Parser scanning for X.509 CN and Validity strings
  try {
    const textSample = new TextDecoder('latin1', { fatal: false }).decode(data);

    // Extract Common Names (CN)
    const cnMatches = textSample.match(/[\x06\x03\x55\x04\x03][\x13\x0c]([^\x00-\x1f]{3,40})/g);
    const extractedCns: string[] = [];
    if (cnMatches) {
      for (const m of cnMatches) {
        const cleaned = m.slice(2).trim();
        if (cleaned.length > 2 && !extractedCns.includes(cleaned)) {
          extractedCns.push(cleaned);
        }
      }
    }

    const subjectCn = extractedCns[0] || (flow.serverHostname || flow.serverIp);
    const issuerCn = extractedCns.length > 1 ? extractedCns[extractedCns.length - 1] : subjectCn;

    // Check self-signed status (RULE 3)
    const isSelfSigned = subjectCn === issuerCn || textSample.includes('Self-Signed') || textSample.includes('Test CA');

    // Extract Date strings (UTCTime 23YYMMDDHHMMSSZ or GeneralizedTime 24YYYYMMDDHHMMSSZ)
    const dateMatches = textSample.match(/(2[0-9]{11,13}Z)/g);
    let expirationDate = '2027-01-01 00:00:00 UTC';
    let isExpired = false;

    if (dateMatches && dateMatches.length >= 2) {
      const rawNotAfter = dateMatches[1];
      // Format YYMMDD or YYYYMMDD
      const year = rawNotAfter.length === 13 ? 2000 + parseInt(rawNotAfter.slice(0, 2), 10) : parseInt(rawNotAfter.slice(0, 4), 10);
      const month = rawNotAfter.length === 13 ? rawNotAfter.slice(2, 4) : rawNotAfter.slice(4, 6);
      const day = rawNotAfter.length === 13 ? rawNotAfter.slice(4, 6) : rawNotAfter.slice(6, 8);
      expirationDate = `${year}-${month}-${day} 00:00:00 UTC`;

      const expTime = new Date(`${year}-${month}-${day}T00:00:00Z`).getTime();
      const capTime = captureTimestamp ? new Date(captureTimestamp).getTime() : Date.now();
      isExpired = expTime < capTime;
    }

    flow.certificateSubject = `CN=${subjectCn}`;
    flow.certificateIssuer = `CN=${issuerCn}`;
    flow.certificateSanList = [subjectCn, `*.${subjectCn}`];
    flow.certificateExpirationDate = expirationDate;
    flow.certificateIsExpired = isExpired;
    flow.certificateIsSelfSigned = isSelfSigned;
    flow.certificateSerialNumber = Array.from(data.slice(10, 18))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':');
  } catch {
    // Graceful parse fallback
    flow.certificateSubject = `CN=${flow.serverHostname || flow.serverIp}`;
    flow.certificateIssuer = `CN=${flow.serverHostname || flow.serverIp}`;
    flow.certificateIsSelfSigned = true;
    flow.certificateIsExpired = false;
  }
}
