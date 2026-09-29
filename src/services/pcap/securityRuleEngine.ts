/**
 * SecureMailScope - Deterministic Security Rule Engine
 * STEP 5: Security Rule Engine (Rules 1 to 6 + RFC 8314)
 * SIH 2026 Problem Statement 26159
 */

import { ParsedPacket, ReconstructedFlow } from './pcapTypes';
import { CryptographicEvidence, Finding } from '../../types/security';

export function evaluateSecurityRules(
  packets: ParsedPacket[],
  flows: ReconstructedFlow[],
  pcapId: string
): { findings: Finding[]; evidenceList: CryptographicEvidence[] } {
  const findings: Finding[] = [];
  const evidenceList: CryptographicEvidence[] = [];

  let findingCounter = 1;
  let evidenceCounter = 1;

  // RULE 6: IPv4 Fragmentation Detected
  // Condition: IPv4 packet has More Fragments (MF) flag set OR Fragment Offset > 0
  const fragmentedPackets = packets.filter((p) => p.ipv4Fragmented);
  if (fragmentedPackets.length > 0) {
    const frameNumbers = fragmentedPackets.map((p) => p.frameNumber);
    const evId = `EVD-FRAG-${evidenceCounter++}`;

    evidenceList.push({
      id: evId,
      sessionId: 'NET-IPV4',
      pcapId,
      evidenceType: 'KEY_EXCHANGE',
      rawObservation: `IPv4 Fragmentation detected across ${fragmentedPackets.length} datagram(s). First instance in Frame #${frameNumbers[0]} with offset ${fragmentedPackets[0].ipv4FragmentOffset} bytes.`,
      packetFrameNumbers: frameNumbers.slice(0, 10),
      byteOffsetHex: `0x0006`,
      hexDumpSample: fragmentedPackets[0].hexDumpPreview,
      confidence: 'COMPLETE',
      confidenceExplanation: 'IPv4 flags field in packet header explicitly asserts More Fragments (MF) or non-zero Fragment Offset.',
      verifiedTimestamp: new Date().toISOString(),
      authoritativeStandard: 'RFC 791 Section 3.2'
    });

    findings.push({
      id: `FIND-RULE-6-${findingCounter++}`,
      title: 'IPv4 Fragmentation Observed',
      severity: 'LOW',
      confidence: 'COMPLETE',
      affectedSessionId: 'NET-IPV4',
      evidenceIds: [evId],
      ruleId: 'RULE-IPV4-006',
      ruleTitle: 'IPv4 Fragmentation Policy Check',
      standardReference: 'RFC 791 Section 3.2 / NIST SP 800-52r2',
      evidenceStatement: `Observed ${fragmentedPackets.length} fragmented IPv4 datagram(s) in Frame #${frameNumbers.join(', #')}.`,
      technicalReason: 'IPv4 fragmentation was observed on the wire. While permissible in standard IP networking, packet fragmentation can be leveraged for firewall evasion or indicate suboptimal MTU/PMTU discovery settings.',
      securityImpact: 'Potential exposure to IP reassembly denial-of-service or NIDS/firewall state evasion.',
      recommendedAction: 'Verify Path MTU Discovery (PMTUD) and tune network interface MTUs to avoid in-transit fragmentation.',
      priorityOrder: 5,
      remediationComplexity: 'LOW',
      status: 'OPEN',
      evidenceClass: 'OBSERVED',
      observedValue: `Fragment count: ${fragmentedPackets.length}`,
      expectedPolicyValue: 'DF=1, No In-Transit Fragmentation'
    });
  }

  // Iterate over reconstructed flows
  for (const flow of flows) {
    const sessionId = `SES-${flow.streamIndex + 1}`;

    // RULE 1: Deprecated TLS Version
    // Condition: TLS version == 1.0 OR 1.1
    if (flow.tlsVersion === 'TLS 1.0' || flow.tlsVersion === 'TLS 1.1') {
      const tlsPkt = flow.packets.find((p) => p.detectedAppProtocol === 'TLS') || flow.packets[0];
      const evId = `EVD-TLS-${evidenceCounter++}`;

      evidenceList.push({
        id: evId,
        sessionId,
        pcapId,
        evidenceType: 'TLS_VERSION',
        rawObservation: `Negotiated protocol version is ${flow.tlsVersion} (Code: 0x0${flow.tlsVersionCode?.toString(16)}).`,
        packetFrameNumbers: [tlsPkt.frameNumber],
        byteOffsetHex: '0x0009',
        hexDumpSample: tlsPkt.hexDumpPreview,
        confidence: 'COMPLETE',
        confidenceExplanation: 'Server Hello handshake record explicitly selects legacy protocol version.',
        verifiedTimestamp: new Date().toISOString(),
        authoritativeStandard: 'RFC 8996 (BCP 195)'
      });

      findings.push({
        id: `FIND-RULE-1-${findingCounter++}`,
        title: 'Deprecated TLS Version',
        severity: 'HIGH',
        confidence: 'COMPLETE',
        affectedSessionId: sessionId,
        evidenceIds: [evId],
        ruleId: 'RULE-TLS-001',
        ruleTitle: 'Deprecated TLS Protocol Policy Check',
        standardReference: 'RFC 8996 / RFC 9325 (BCP 195)',
        evidenceStatement: `Session negotiated ${flow.tlsVersion} in Frame #${tlsPkt.frameNumber}.`,
        technicalReason: `${flow.tlsVersion} is formally deprecated by IETF RFC 8996 and prohibited by RFC 9325 due to lack of AEAD ciphers and susceptibility to protocol downgrade attacks.`,
        securityImpact: 'Loss of confidentiality and failure of regulatory cryptographic compliance standards.',
        recommendedAction: 'Configure the mail transfer daemon to enforce a minimum of TLS 1.2 or TLS 1.3.',
        priorityOrder: 2,
        remediationComplexity: 'LOW',
        status: 'OPEN',
        evidenceClass: 'OBSERVED',
        observedValue: flow.tlsVersion,
        expectedPolicyValue: 'TLS 1.2 or TLS 1.3'
      });
    }

    // RULE 2: Certificate Expired
    // Condition: Certificate expired
    if (flow.certificateIsExpired && flow.certificateExpirationDate) {
      const certPkt = flow.packets.find((p) => p.detectedAppProtocol === 'TLS') || flow.packets[0];
      const evId = `EVD-CERT-EXP-${evidenceCounter++}`;

      evidenceList.push({
        id: evId,
        sessionId,
        pcapId,
        evidenceType: 'CERTIFICATE',
        rawObservation: `X.509 Certificate expired on ${flow.certificateExpirationDate}. Subject: ${flow.certificateSubject}.`,
        packetFrameNumbers: [certPkt.frameNumber],
        byteOffsetHex: '0x002B',
        hexDumpSample: certPkt.hexDumpPreview,
        confidence: 'COMPLETE',
        confidenceExplanation: 'Validity period notAfter field in presented X.509 certificate precedes capture timestamp.',
        verifiedTimestamp: new Date().toISOString(),
        authoritativeStandard: 'RFC 5280 Section 4.1.2.5'
      });

      findings.push({
        id: `FIND-RULE-2-${findingCounter++}`,
        title: 'Expired Certificate',
        severity: 'HIGH',
        confidence: 'COMPLETE',
        affectedSessionId: sessionId,
        evidenceIds: [evId],
        ruleId: 'RULE-CERT-001',
        ruleTitle: 'Certificate Expiration Policy Check',
        standardReference: 'RFC 5280 Section 4.1.2.5',
        evidenceStatement: `Certificate for ${flow.certificateSubject} expired on ${flow.certificateExpirationDate}.`,
        technicalReason: 'The server presented an X.509 certificate whose validity window (notAfter) has lapsed, breaking mutual cryptographic trust.',
        securityImpact: 'Connecting clients will reject the connection or prompt users with security bypass warnings.',
        recommendedAction: 'Renew and install a current X.509 certificate from a trusted Certificate Authority.',
        priorityOrder: 2,
        remediationComplexity: 'LOW',
        status: 'OPEN',
        evidenceClass: 'OBSERVED',
        observedValue: `Expired: ${flow.certificateExpirationDate}`,
        expectedPolicyValue: 'Valid Unexpired Certificate'
      });
    }

    // RULE 3: Suspicious Certificate (Self-Signed)
    // Condition: Self-signed certificate
    if (flow.certificateIsSelfSigned) {
      const certPkt = flow.packets.find((p) => p.detectedAppProtocol === 'TLS') || flow.packets[0];
      const evId = `EVD-CERT-SELF-${evidenceCounter++}`;

      evidenceList.push({
        id: evId,
        sessionId,
        pcapId,
        evidenceType: 'CERTIFICATE',
        rawObservation: `Self-signed X.509 Certificate detected: Issuer matches Subject (${flow.certificateSubject}).`,
        packetFrameNumbers: [certPkt.frameNumber],
        byteOffsetHex: '0x001A',
        hexDumpSample: certPkt.hexDumpPreview,
        confidence: 'COMPLETE',
        confidenceExplanation: 'Certificate Issuer DN is identical to Subject DN without public CA chaining.',
        verifiedTimestamp: new Date().toISOString(),
        authoritativeStandard: 'CAB Forum Baseline Requirements / RFC 5280'
      });

      findings.push({
        id: `FIND-RULE-3-${findingCounter++}`,
        title: 'Suspicious Certificate',
        severity: 'MEDIUM',
        confidence: 'COMPLETE',
        affectedSessionId: sessionId,
        evidenceIds: [evId],
        ruleId: 'RULE-CERT-003',
        ruleTitle: 'Untrusted Trust Chain Policy Check',
        standardReference: 'CAB Forum Baseline Requirements / RFC 5280',
        evidenceStatement: `Certificate for ${flow.certificateSubject} is self-signed.`,
        technicalReason: 'The presented certificate does not chain to a publicly trusted root Certificate Authority.',
        securityImpact: 'Vulnerability to Man-In-The-Middle interception due to lack of authenticated identity verification.',
        recommendedAction: 'Replace self-signed certificates with certificates issued by a recognized public or internal corporate PKI CA.',
        priorityOrder: 3,
        remediationComplexity: 'MEDIUM',
        status: 'OPEN',
        evidenceClass: 'OBSERVED',
        observedValue: 'Self-Signed (Issuer == Subject)',
        expectedPolicyValue: 'Trusted CA Chained Certificate'
      });
    }

    // RULE 4: Possible STARTTLS Stripping
    // Condition: STARTTLS advertised but negotiation missing
    if (flow.startTlsAdvertised && !flow.startTlsNegotiated) {
      const advPkt = flow.packets.find((p) => p.payloadLength > 0) || flow.packets[0];
      const evId = `EVD-STRIP-${evidenceCounter++}`;

      evidenceList.push({
        id: evId,
        sessionId,
        pcapId,
        evidenceType: 'STARTTLS_BEHAVIOR',
        rawObservation: `STARTTLS was advertised in server capabilities, but negotiation never completed.`,
        packetFrameNumbers: [advPkt.frameNumber],
        byteOffsetHex: '0x0000',
        hexDumpSample: advPkt.hexDumpPreview,
        confidence: 'COMPLETE',
        confidenceExplanation: 'Server capability response contained STARTTLS, but the subsequent client dialogue did not transition into TLS encryption.',
        verifiedTimestamp: new Date().toISOString(),
        authoritativeStandard: 'RFC 7435 / RFC 8314 Section 3'
      });

      findings.push({
        id: `FIND-RULE-4-${findingCounter++}`,
        title: 'Possible STARTTLS Stripping',
        severity: 'HIGH',
        confidence: 'COMPLETE',
        affectedSessionId: sessionId,
        evidenceIds: [evId],
        ruleId: 'RULE-STARTTLS-002',
        ruleTitle: 'STARTTLS Negotiation Enforcement Check',
        standardReference: 'RFC 7435 / RFC 8314',
        evidenceStatement: `STARTTLS advertised on stream ${sessionId} but plaintext transmission continued.`,
        technicalReason: 'The server advertised opportunistic TLS capability, but the client failed to negotiate STARTTLS, which is a characteristic signature of active network tampering (STARTTLS Stripping) or client misconfiguration.',
        securityImpact: 'Unencrypted communication subject to eavesdropping and data manipulation.',
        recommendedAction: 'Enforce mandatory TLS on submission ports (e.g. port 587/465) and implement MTA-STS / DANE.',
        priorityOrder: 1,
        remediationComplexity: 'MEDIUM',
        status: 'OPEN',
        evidenceClass: 'OBSERVED',
        observedValue: 'Advertised: YES, Negotiated: NO',
        expectedPolicyValue: 'STARTTLS Negotiated or Direct TLS'
      });
    }

    // RULE 5: Weak Cipher Suite Detected
    // Condition: Weak cipher suite detected
    if (flow.cipherSuiteIsWeak && flow.cipherSuiteName) {
      const tlsPkt = flow.packets.find((p) => p.detectedAppProtocol === 'TLS') || flow.packets[0];
      const evId = `EVD-CIPHER-${evidenceCounter++}`;

      evidenceList.push({
        id: evId,
        sessionId,
        pcapId,
        evidenceType: 'CIPHER_SUITE',
        rawObservation: `Weak cipher suite negotiated: ${flow.cipherSuiteName}. Forward Secrecy: ${flow.forwardSecrecy ? 'YES' : 'NO'}.`,
        packetFrameNumbers: [tlsPkt.frameNumber],
        byteOffsetHex: '0x002F',
        hexDumpSample: tlsPkt.hexDumpPreview,
        confidence: 'COMPLETE',
        confidenceExplanation: 'Server Hello selected cipher suite code matching known weak or non-PFS cryptographic suites.',
        verifiedTimestamp: new Date().toISOString(),
        authoritativeStandard: 'NIST SP 800-52r2 / RFC 7525'
      });

      findings.push({
        id: `FIND-RULE-5-${findingCounter++}`,
        title: 'Weak Cipher Suite',
        severity: 'MEDIUM',
        confidence: 'COMPLETE',
        affectedSessionId: sessionId,
        evidenceIds: [evId],
        ruleId: 'RULE-CIPHER-002',
        ruleTitle: 'Cryptographic Cipher Strength Policy Check',
        standardReference: 'NIST SP 800-52r2 / RFC 7525 (BCP 195)',
        evidenceStatement: `Negotiated cipher ${flow.cipherSuiteName} in Frame #${tlsPkt.frameNumber}.`,
        technicalReason: `The negotiated cipher suite (${flow.cipherSuiteName}) relies on legacy algorithms or lacks Forward Secrecy, violating NIST SP 800-52r2 guidelines.`,
        securityImpact: 'Susceptibility to cipher collision attacks or retroactive session decryption.',
        recommendedAction: 'Disable legacy CBC, 3DES, and static RSA ciphers; require AEAD ciphers with ECDHE key agreement.',
        priorityOrder: 3,
        remediationComplexity: 'LOW',
        status: 'OPEN',
        evidenceClass: 'OBSERVED',
        observedValue: flow.cipherSuiteName,
        expectedPolicyValue: 'AEAD Cipher with Forward Secrecy (ECDHE)'
      });
    }

    // RULE 7: Cleartext Credentials Exposed (RFC 8314)
    if (flow.plaintextCredentialsExposed) {
      const plainPkt = flow.packets.find((p) => p.payloadLength > 0) || flow.packets[0];
      const evId = `EVD-PLAIN-${evidenceCounter++}`;

      evidenceList.push({
        id: evId,
        sessionId,
        pcapId,
        evidenceType: 'PLAINTEXT_EXPOSURE',
        rawObservation: flow.exposedCredentialsDetails || 'Plaintext authentication command transmitted without TLS.',
        packetFrameNumbers: [plainPkt.frameNumber],
        byteOffsetHex: '0x0000',
        hexDumpSample: plainPkt.hexDumpPreview,
        confidence: 'COMPLETE',
        confidenceExplanation: 'Cleartext ASCII password or authentication credentials extracted directly from application wire payload.',
        verifiedTimestamp: new Date().toISOString(),
        authoritativeStandard: 'RFC 8314 Section 3'
      });

      findings.push({
        id: `FIND-RULE-7-${findingCounter++}`,
        title: 'Plaintext Credentials Exposed',
        severity: 'CRITICAL',
        confidence: 'COMPLETE',
        affectedSessionId: sessionId,
        evidenceIds: [evId],
        ruleId: 'RULE-PLAIN-001',
        ruleTitle: 'Cleartext Authentication Exposure Check',
        standardReference: 'RFC 8314 Section 3',
        evidenceStatement: `Plaintext credentials captured in Frame #${plainPkt.frameNumber}.`,
        technicalReason: 'Mailbox authentication was performed over an unencrypted cleartext stream without TLS encapsulation, directly exposing user credentials to network interception.',
        securityImpact: 'Critical credential compromise allowing unauthorized account access and data exfiltration.',
        recommendedAction: 'Immediately terminate unencrypted protocol access and enforce implicit TLS (e.g. port 995 for POP3, port 993 for IMAP, port 465/587 for SMTP).',
        priorityOrder: 1,
        remediationComplexity: 'HIGH',
        status: 'OPEN',
        evidenceClass: 'OBSERVED',
        observedValue: 'Unencrypted USER/PASS or AUTH in wire frame',
        expectedPolicyValue: 'Encrypted TLS Tunnel'
      });
    }
  }

  return { findings, evidenceList };
}
