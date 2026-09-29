/**
 * SecureMailScope - Demonstration Scenarios & Forensic Dataset
 * SIH 2026 Problem Statement 26159
 * All scenarios are labelled as DEMONSTRATION SCENARIOS for research and evaluation.
 */

import { DemoScenario, DeterministicRule, PipelineStage } from '../types/security';

export const DETERMINISTIC_RULES: DeterministicRule[] = [
  {
    ruleId: 'RULE-TLS-001',
    title: 'Deprecated TLS Protocol Version Policy',
    standardReference: 'RFC 8996 (BCP 195) / RFC 9325 / NIST SP 800-52r2 Section 3.1',
    authoritativeAuthority: 'IETF (BCP 195) & NIST',
    logicExpression: 'session.tls_version IN ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]',
    severityDefault: 'HIGH',
    description: 'RFC 8996 formally deprecated TLS 1.0 and TLS 1.1 in March 2021. Legacy protocol versions lack support for modern authenticated encryption and are susceptible to downgrade attacks and padding oracle exploits. RFC 9325 mandates TLS 1.2 or TLS 1.3.'
  },
  {
    ruleId: 'RULE-CIPHER-002',
    title: 'Obsolete Block Cipher Suite Prohibition (3DES / RC4 / DES)',
    standardReference: 'RFC 9325 Section 4.2 (BCP 195) / RFC 8996 Section 2 / CVE-2016-2183 (Sweet32) / NIST SP 800-131Ar2',
    authoritativeAuthority: 'IETF & NIST',
    logicExpression: 'cipher.encryption IN ["3DES", "RC4", "DES", "IDEA"] OR cipher.mode == "CBC"',
    severityDefault: 'HIGH',
    description: 'Triple-DES (3DES) uses a 64-bit block size vulnerable to collision attacks (Sweet32, CVE-2016-2183) after 32GB of data in a single TLS connection. Prohibited by RFC 9325 and disallowed by NIST SP 800-131Ar2 for enterprise encryption.'
  },
  {
    ruleId: 'RULE-CIPHER-003',
    title: 'Ephemeral Key Exchange Mandate (Forward Secrecy Enforcement)',
    standardReference: 'RFC 9325 Section 4.1 (BCP 195) / NIST SP 800-52r2 Section 3.3.1 / BSI TR-02102-2',
    authoritativeAuthority: 'IETF (BCP 195), NIST & BSI',
    logicExpression: 'cipher.keyExchange NOT IN ["ECDHE", "DHE"]',
    severityDefault: 'HIGH',
    description: 'Static RSA key exchange does not provide Forward Secrecy (PFS). If the server private key is compromised in the future, adversaries with passively recorded PCAPs can retroactively decrypt all past email traffic.'
  },
  {
    ruleId: 'RULE-CERT-001',
    title: 'X.509 Certificate Validity Period & Expiry Enforcement',
    standardReference: 'RFC 5280 Section 4.1.2.5 / CA/Browser Forum TLS Baseline Requirements 7.1.4',
    authoritativeAuthority: 'IETF (RFC 5280) & CA/Browser Forum',
    logicExpression: 'now() > cert.validUntil OR now() < cert.validFrom',
    severityDefault: 'HIGH',
    description: 'Expired certificates break cryptographic trust validation. Mail Transfer Agents (MTAs) and clients cannot verify the identity of the remote mail host, exposing communications to active Man-in-the-Middle (MitM) impersonation.'
  },
  {
    ruleId: 'RULE-CERT-004',
    title: 'Deprecated Weak Hash Algorithm in X.509 Signature (SHA-1 / MD5)',
    standardReference: 'RFC 9325 Section 4.3 / NIST Policy on SHA-1 Deprecation / CAB Forum BR 7.1.3',
    authoritativeAuthority: 'IETF, NIST & CA/Browser Forum',
    logicExpression: 'cert.signatureAlgorithm IN ["sha1WithRSAEncryption", "md5WithRSAEncryption"]',
    severityDefault: 'HIGH',
    description: 'SHA-1 has known practical collision vulnerabilities (SHAttered, Shambles). Certificates signed with SHA-1 are rejected by modern cryptographic libraries and root stores.'
  },
  {
    ruleId: 'RULE-PLAIN-001',
    title: 'Cleartext Mail Protocol Transport & Credential Exposure',
    standardReference: 'RFC 8314 Section 3 (Cleartext Considered Obsolete for Email Submission and Access)',
    authoritativeAuthority: 'IETF (RFC 8314)',
    logicExpression: 'session.protocol IN ["POP3", "IMAP", "SMTP"] AND session.startTlsNegotiated == false AND session.directTls == false',
    severityDefault: 'CRITICAL',
    description: 'RFC 8314 specifies that cleartext email protocols must not be used on the Internet. Plaintext sessions expose user authentication credentials (USER/PASS or AUTH PLAIN) and message payloads to any network eavesdropper.'
  },
  {
    ruleId: 'RULE-STARTTLS-002',
    title: 'Opportunistic STARTTLS Without Downgrade Defense (MTA-STS / DANE Missing)',
    standardReference: 'RFC 8461 (MTA-STS) & RFC 7672 (DANE SMTP) / RFC 3207',
    authoritativeAuthority: 'IETF (RFC 8461 & RFC 7672)',
    logicExpression: 'startTlsAdvertised == true AND startTlsRequested == false',
    severityDefault: 'MEDIUM',
    description: 'Opportunistic STARTTLS without MTA-STS (RFC 8461) or DANE (RFC 7672) DNSSEC verification allows network adversaries to strip the 250-STARTTLS advertisement (STRIPTLS attack), silently falling back to unencrypted cleartext.'
  },
  {
    ruleId: 'RULE-PCAP-009',
    title: 'Observation Truncation & Insufficient Packet Capture Window',
    standardReference: 'ISO/IEC 27037:2012 (Digital Evidence Forensics)',
    authoritativeAuthority: 'ISO/IEC 27037 Digital Forensics Quality Baseline',
    logicExpression: 'session.streamIncomplete == true OR handshakeState == "TRUNCATED"',
    severityDefault: 'LOW',
    description: 'Cryptographic conclusions require complete protocol handshakes. Incomplete packet captures prevent definitive verification of certificate chains and cipher negotiations.'
  }
];

const RAW_SCENARIOS: DemoScenario[] = [
  // SCENARIO 1: Secure SMTP (Modern TLS 1.3 Baseline)
  {
    id: 'scenario-secure-smtp',
    title: 'Scenario 1: Modern Secure SMTP Transport (TLS 1.3)',
    subtitle: 'SMTP Port 587 · STARTTLS · TLS_AES_256_GCM_SHA384 · ECDHE X25519',
    description: 'Fully compliant mail submission session demonstrating modern email cryptographic posture adhering to RFC 9846 (TLS 1.3), forward secrecy, and strict X.509 validation.',
    defaultSelectedSessionId: 'SES-001',
    pcapMetadata: {
      id: 'PCAP-2026-001',
      filename: 'modern_submission_smtp_tls13.pcapng',
      sha256: '9a40e11893bf4098ca30e9d4810fb82a01349a21b3439908cf82187a4192bc01',
      fileSizeBytes: 1845200,
      captureTimestamp: '2026-09-24 09:30:15 UTC',
      analysisTimestamp: '2026-09-24 09:31:00 UTC',
      packetCount: 940,
      streamCount: 6,
      status: 'VERIFIED',
      confidence: 'COMPLETE',
      capturedInterface: 'ens192 (Edge DMZ Tap)',
      notes: 'Standard production capture. High cryptographic integrity.',
      sha256VerificationState: 'COMPUTED',
      captureDurationSec: 2.45,
      totalTcpFlows: 6,
      completeSessionsCount: 1,
      partialSessionsCount: 0,
      truncatedSessionsCount: 0,
      tlsHandshakeCount: 1,
      truncatedHandshakeCount: 0,
      missingPacketsCount: 0
    },
    sessions: [
      {
        id: 'SES-001',
        pcapId: 'PCAP-2026-001',
        protocol: 'SMTP',
        sourceIp: '10.0.0.15',
        sourcePort: 49122,
        destIp: '198.51.100.25',
        destPort: 587,
        serverHostname: 'mail.secure-enterprise.org',
        startTlsAdvertised: true,
        startTlsRequested: true,
        startTlsNegotiated: true,
        risk: 'LOW',
        evidenceConfidence: 'COMPLETE',
        evidenceConfidenceReason: 'Bidirectional TLS 1.3 handshake captured in full.',
        durationSec: 2.45,
        timestamp: '2026-09-24 09:30:15.110 UTC',
        findingsIds: ['FIND-001-INFO'],
        evidenceIds: ['EVD-001-TLS', 'EVD-001-CERT'],
        bannerText: '220 mail.secure-enterprise.org ESMTP Postfix (Secure Submission)',
        clientSoftware: 'Thunderbird/128.0',
        tlsHandshake: {
          negotiatedVersion: 'TLS 1.3',
          isDeprecatedVersion: false,
          cipherSuite: {
            ianaName: 'TLS_AES_256_GCM_SHA384',
            rfcCode: '0x1302',
            keyExchange: 'ECDHE (X25519 Curve)',
            encryption: 'AES-256-GCM (Authenticated)',
            mac: 'AEAD (Built-in GCM)',
            forwardSecrecy: true,
            isWeak: false
          },
          forwardSecrecy: true,
          sni: 'mail.secure-enterprise.org',
          alpn: 'smtp',
          sessionResumed: false,
          certificate: {
            serialNumber: '04:77:E1:92:AA:BC:09:41',
            subject: 'CN=mail.secure-enterprise.org, O=Secure Enterprise Corp, C=US',
            subjectCommonName: 'mail.secure-enterprise.org',
            issuer: 'CN=Let\'s Encrypt Authority E6, O=Let\'s Encrypt, C=US',
            issuerCommonName: 'Let\'s Encrypt Authority E6',
            validFrom: '2026-08-01 00:00:00 UTC',
            validUntil: '2026-11-01 23:59:59 UTC',
            isExpired: false,
            daysUntilExpiry: 37,
            publicKeyAlgorithm: 'RSA',
            keyLengthBits: 4096,
            signatureAlgorithm: 'sha256WithRSAEncryption',
            isWeakKey: false,
            isWeakSignature: false,
            chainStatus: 'VALID',
            sanList: ['mail.secure-enterprise.org', 'smtp.secure-enterprise.org'],
            fingerprintSha256: '3E:89:12:00:AB:44:91:34:55:01:8A:BC:DD:EE:FF:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11'
          },
          handshakeMessages: [
            { name: 'ClientHello', stage: 'TLS_HANDSHAKE', frameNumber: 10, status: 'OBSERVED', description: 'TLS 1.3 Client Hello offering X25519 KeyShare and SupportedVersions (0x0304)' },
            { name: 'ServerHello', stage: 'TLS_HANDSHAKE', frameNumber: 12, status: 'OBSERVED', description: 'TLS 1.3 Server Hello selecting 0x0304, Cipher 0x1302, and server X25519 KeyShare' },
            { name: 'EncryptedExtensions', stage: 'TLS_HANDSHAKE', frameNumber: 12, status: 'OBSERVED', description: 'Encrypted protocol extensions negotiated (ALPN: smtp)' },
            { name: 'Certificate', stage: 'TLS_HANDSHAKE', frameNumber: 12, status: 'OBSERVED', description: 'Presented 4096-bit RSA X.509 server certificate issued by Let\'s Encrypt E6' },
            { name: 'CertificateVerify', stage: 'TLS_HANDSHAKE', frameNumber: 12, status: 'OBSERVED', description: 'Server digital signature proving private key possession' },
            { name: 'Finished', stage: 'TLS_HANDSHAKE', frameNumber: 14, status: 'OBSERVED', description: 'Handshake completed with mutual Finished records (1-RTT round-trip)' }
          ]
        },
        protocolEvents: [
          {
            id: 'EVT-S01',
            timestamp: '09:30:15.110',
            relativeMs: 0,
            direction: 'INTERNAL',
            stage: 'TCP',
            title: 'TCP Handshake Completed',
            detail: 'Client port 49122 connected to server port 587.',
            packetNumber: 1,
            tcpStreamIndex: 1
          },
          {
            id: 'EVT-S02',
            timestamp: '09:30:15.135',
            relativeMs: 25,
            direction: 'SERVER_TO_CLIENT',
            stage: 'BANNER',
            title: 'SMTP Submission Banner',
            payloadPreview: '220 mail.secure-enterprise.org ESMTP Postfix',
            detail: 'Server banner received on submission port 587.',
            packetNumber: 3,
            tcpStreamIndex: 1
          },
          {
            id: 'EVT-S03',
            timestamp: '09:30:15.170',
            relativeMs: 60,
            direction: 'SERVER_TO_CLIENT',
            stage: 'STARTTLS',
            title: 'STARTTLS Extension Advertised',
            payloadPreview: '250-STARTTLS\n250-AUTH PLAIN LOGIN',
            detail: 'Server advertises STARTTLS and requires security before authentication.',
            packetNumber: 7,
            tcpStreamIndex: 1
          },
          {
            id: 'EVT-S04',
            timestamp: '09:30:15.220',
            relativeMs: 110,
            direction: 'SERVER_TO_CLIENT',
            stage: 'TLS_HANDSHAKE',
            title: 'TLS 1.3 Negotiated with AES-256-GCM',
            payloadPreview: 'Server Hello: Supported Versions extension selected 0x0304 (TLS 1.3)',
            detail: 'Modern TLS 1.3 protocol established with ephemeral X25519 key share.',
            packetNumber: 14,
            tcpStreamIndex: 1
          }
        ]
      }
    ],
    findings: [
      {
        id: 'FIND-001-INFO',
        title: 'Nominal Cryptographic Posture (TLS 1.3 + Forward Secrecy Verified)',
        severity: 'INFORMATIONAL',
        confidence: 'COMPLETE',
        affectedSessionId: 'SES-001',
        evidenceIds: ['EVD-001-TLS', 'EVD-001-CERT'],
        ruleId: 'RULE-TLS-001',
        ruleTitle: 'Modern Cryptographic Baseline Verification',
        standardReference: 'RFC 9846 (TLS 1.3, obsoletes RFC 8446) / RFC 9852 (BCP 195)',
        evidenceClass: 'ASSESSED',
        observedValue: 'TLS 1.3 (Record 0x0304) with TLS_AES_256_GCM_SHA384 and X25519 Ephemeral Key Share',
        expectedPolicyValue: 'TLS 1.3 with authenticated encryption and Forward Secrecy',
        policyProfile: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
        evidenceStatement: 'Handshake negotiation confirmed TLS 1.3 with authenticated encryption (AES-256-GCM) and X25519 ephemeral key agreement.',
        technicalReason: 'Session satisfies all modern enterprise cryptographic standards. Perfect Forward Secrecy protects communications against retroactive compromise.',
        securityImpact: 'No adverse impact detected. Security posture is robust.',
        recommendedAction: 'Maintain current configuration and monitor certificate renewal cadence prior to 30-day window.',
        priorityOrder: 99,
        remediationComplexity: 'LOW',
        status: 'RESOLVED',
        forensicLimitations: 'Confirmed in captured session SES-001.'
      }
    ],
    evidenceList: [
      {
        id: 'EVD-001-TLS',
        sessionId: 'SES-001',
        pcapId: 'PCAP-2026-001',
        evidenceType: 'TLS_VERSION',
        rawObservation: 'TLS 1.3 Handshake completed. Cipher: TLS_AES_256_GCM_SHA384 (0x1302), Key Share: X25519',
        packetFrameNumbers: [10, 14],
        byteOffsetHex: '0x000000C8',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Full TLS 1.3 1-RTT handshake captured with encrypted extensions and finished verify_data.',
        verifiedTimestamp: '2026-09-24 09:30:15.220 UTC',
        authoritativeStandard: 'RFC 9846 (TLS 1.3)'
      },
      {
        id: 'EVD-001-CERT',
        sessionId: 'SES-001',
        pcapId: 'PCAP-2026-001',
        evidenceType: 'CERTIFICATE',
        rawObservation: 'Valid Certificate: CN=mail.secure-enterprise.org, RSA 4096-bit, SHA-256, 37 days validity remaining',
        packetFrameNumbers: [16],
        byteOffsetHex: '0x000001A0',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Certificate chain verified against Mozilla trusted root store.',
        verifiedTimestamp: '2026-09-24 09:30:15.240 UTC',
        authoritativeStandard: 'RFC 5280'
      }
    ],
    rules: DETERMINISTIC_RULES
  },

  // SCENARIO 2 (Default Featured Demo): Deprecated TLS 1.0 & 3DES
  {
    id: 'scenario-legacy-smtp',
    title: 'Scenario 2: Deprecated TLS 1.0 on Exchange MTA',
    subtitle: 'SMTP Port 25 · STARTTLS · Sweet32 3DES-CBC · Static RSA',
    description: 'Passively captured inbound relay traffic from enterprise edge gateway exhibiting legacy TLS 1.0 negotiation, 3DES cipher suites, and complete lack of Forward Secrecy.',
    defaultSelectedSessionId: 'SES-014',
    pcapMetadata: {
      id: 'PCAP-2026-002',
      filename: 'exchange_edge_smtp_tls10_sweet32.pcapng',
      sha256: '7b2a9f4c3d81e05a8b291ca8234fd6e902187a552bf891c01e9a38210459a112',
      fileSizeBytes: 2489104,
      captureTimestamp: '2026-09-24 10:01:02 UTC',
      analysisTimestamp: '2026-09-24 10:02:15 UTC',
      packetCount: 1420,
      streamCount: 18,
      status: 'VERIFIED',
      confidence: 'COMPLETE',
      capturedInterface: 'eth0 (Passive SPAN Mirror)',
      notes: 'Clean full-duplex tap capture. All TCP streams reconstructed without segment loss.',
      sha256VerificationState: 'COMPUTED',
      captureDurationSec: 14.8,
      totalTcpFlows: 18,
      completeSessionsCount: 2,
      partialSessionsCount: 0,
      truncatedSessionsCount: 0,
      tlsHandshakeCount: 2,
      truncatedHandshakeCount: 0,
      missingPacketsCount: 0
    },
    sessions: [
      {
        id: 'SES-014',
        pcapId: 'PCAP-2026-002',
        protocol: 'SMTP',
        sourceIp: '198.51.100.44',
        sourcePort: 51240,
        destIp: '203.0.113.25',
        destPort: 25,
        serverHostname: 'mail.legacy-corp.example.com',
        startTlsAdvertised: true,
        startTlsRequested: true,
        startTlsNegotiated: true,
        risk: 'HIGH',
        evidenceConfidence: 'COMPLETE',
        evidenceConfidenceReason: 'Full bidirectional TCP stream captured, including complete TLS Client Hello, Server Hello, Certificate, and Finished frames.',
        durationSec: 4.82,
        timestamp: '2026-09-24 10:01:02.140 UTC',
        findingsIds: ['FIND-014', 'FIND-015', 'FIND-016'],
        evidenceIds: ['EVD-014-TLS', 'EVD-014-CIPHER', 'EVD-014-PFS', 'EVD-014-CERT'],
        bannerText: '220 mail.legacy-corp.example.com Microsoft ESMTP MAIL Service ready at Tue, 24 Sep 2026 10:01:03',
        clientSoftware: 'Postfix/3.5.8 relay agent',
        tlsHandshake: {
          negotiatedVersion: 'TLS 1.0',
          isDeprecatedVersion: true,
          cipherSuite: {
            ianaName: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
            rfcCode: '0x000A',
            keyExchange: 'RSA (Static)',
            encryption: '3DES (Triple-DES 168-bit / 112-bit effective)',
            mac: 'HMAC-SHA1',
            forwardSecrecy: false,
            isWeak: true,
            weaknessReason: 'Sweet32 64-bit block collision vulnerability (CVE-2016-2183); Static RSA key exchange lacks forward secrecy.'
          },
          forwardSecrecy: false,
          sni: 'mail.legacy-corp.example.com',
          alpn: 'smtp',
          sessionResumed: false,
          certificate: {
            serialNumber: '3A:89:1F:B2:44:00:81:72',
            subject: 'CN=mail.legacy-corp.example.com, O=Legacy Corp Enterprise, C=US',
            subjectCommonName: 'mail.legacy-corp.example.com',
            issuer: 'CN=Legacy Corp Internal Root CA v2, O=Legacy Corp, C=US',
            issuerCommonName: 'Legacy Corp Internal Root CA v2',
            validFrom: '2024-03-01 00:00:00 UTC',
            validUntil: '2027-03-01 23:59:59 UTC',
            isExpired: false,
            daysUntilExpiry: 156,
            publicKeyAlgorithm: 'RSA',
            keyLengthBits: 2048,
            signatureAlgorithm: 'sha256WithRSAEncryption',
            isWeakKey: false,
            isWeakSignature: false,
            chainStatus: 'VALID',
            sanList: ['mail.legacy-corp.example.com', 'smtp.legacy-corp.example.com'],
            fingerprintSha256: '9F:14:B3:68:55:1A:E0:21:49:10:CC:72:EE:94:01:B7:A8:12:33:51:77:80:BC:EA:11:09:44:F1:60:DE:88:99'
          },
          handshakeMessages: [
            { name: 'ClientHello', stage: 'TLS_HANDSHAKE', frameNumber: 30, status: 'OBSERVED', description: 'TLS 1.0 Client Hello offering 18 cipher suites' },
            { name: 'ServerHello', stage: 'TLS_HANDSHAKE', frameNumber: 34, status: 'OBSERVED', description: 'Selected version TLS 1.0 (0x0301), Cipher 0x000A' },
            { name: 'Certificate', stage: 'TLS_HANDSHAKE', frameNumber: 34, status: 'OBSERVED', description: 'Presented 2048-bit RSA X.509 server certificate' },
            { name: 'ServerKeyExchange', stage: 'TLS_HANDSHAKE', status: 'UNAVAILABLE', description: 'Not transmitted: Static RSA key exchange does not send ServerKeyExchange' },
            { name: 'ServerHelloDone', stage: 'TLS_HANDSHAKE', frameNumber: 34, status: 'OBSERVED', description: 'Handshake negotiation turn relinquished to client' },
            { name: 'ClientKeyExchange', stage: 'TLS_HANDSHAKE', frameNumber: 42, status: 'OBSERVED', description: 'EncryptedPreMasterSecret payload (256 bytes) encrypted with server public RSA key' },
            { name: 'ChangeCipherSpec', stage: 'TLS_HANDSHAKE', frameNumber: 44, status: 'OBSERVED', description: 'Signals subsequent records encrypted under negotiated 3DES keys' },
            { name: 'Finished', stage: 'TLS_HANDSHAKE', frameNumber: 44, status: 'OBSERVED', description: 'Verify data authenticated under negotiated symmetric keys' }
          ]
        },
        protocolEvents: [
          {
            id: 'EVT-01',
            timestamp: '10:01:02.140',
            relativeMs: 0,
            direction: 'INTERNAL',
            stage: 'TCP',
            title: 'TCP Connection Established (3-Way Handshake)',
            detail: 'SYN -> SYN/ACK -> ACK between 198.51.100.44:51240 and 203.0.113.25:25 (RTT: 28.4ms)',
            packetNumber: 12,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-02',
            timestamp: '10:01:02.180',
            relativeMs: 40,
            direction: 'SERVER_TO_CLIENT',
            stage: 'BANNER',
            title: 'SMTP Server Banner Received',
            payloadPreview: '220 mail.legacy-corp.example.com Microsoft ESMTP MAIL Service ready',
            detail: 'Server advertises Microsoft ESMTP software running on TCP port 25.',
            packetNumber: 15,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-03',
            timestamp: '10:01:02.215',
            relativeMs: 75,
            direction: 'CLIENT_TO_SERVER',
            stage: 'GREETING',
            title: 'EHLO Transmission',
            payloadPreview: 'EHLO relay-gateway.partner.com',
            detail: 'Client initiates extended SMTP greeting.',
            packetNumber: 18,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-04',
            timestamp: '10:01:02.245',
            relativeMs: 105,
            direction: 'SERVER_TO_CLIENT',
            stage: 'STARTTLS',
            title: 'STARTTLS Extension Advertised',
            payloadPreview: '250-STARTTLS\n250-PIPELINING\n250-SIZE 52428800',
            detail: 'Server capabilities include STARTTLS (RFC 3207).',
            packetNumber: 21,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-05',
            timestamp: '10:01:02.280',
            relativeMs: 140,
            direction: 'CLIENT_TO_SERVER',
            stage: 'STARTTLS',
            title: 'STARTTLS Command Issued',
            payloadPreview: 'STARTTLS',
            detail: 'Client requests immediate transport security upgrade.',
            packetNumber: 24,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-06',
            timestamp: '10:01:02.310',
            relativeMs: 170,
            direction: 'SERVER_TO_CLIENT',
            stage: 'STARTTLS',
            title: 'STARTTLS Ready Response (220)',
            payloadPreview: '220 2.0.0 Ready to start TLS',
            detail: 'Server confirms TLS state transition; subsequent bytes on stream are TLS record frames.',
            packetNumber: 27,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-07',
            timestamp: '10:01:02.345',
            relativeMs: 205,
            direction: 'CLIENT_TO_SERVER',
            stage: 'TLS_HANDSHAKE',
            title: 'TLS Client Hello Dispatched',
            payloadPreview: 'TLS Record: Handshake (Type 1: Client Hello), Client Version: 0x0301 (TLS 1.0)',
            detail: 'Client advertises supported ciphers and versions including legacy TLS 1.0 fallback.',
            packetNumber: 30,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-08',
            timestamp: '10:01:02.385',
            relativeMs: 245,
            direction: 'SERVER_TO_CLIENT',
            stage: 'TLS_HANDSHAKE',
            title: 'TLS Server Hello: Deprecated TLS 1.0 Negotiated',
            payloadPreview: 'Server Version: 0x0301 (TLS 1.0), Cipher: 0x000A (TLS_RSA_WITH_3DES_EDE_CBC_SHA)',
            isWeaknessOrAnomaly: true,
            detail: 'CRITICAL FORENSIC OBSERVATION: Server selects TLS 1.0 and 3DES-CBC cipher.',
            packetNumber: 34,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-09',
            timestamp: '10:01:02.420',
            relativeMs: 280,
            direction: 'SERVER_TO_CLIENT',
            stage: 'TLS_HANDSHAKE',
            title: 'X.509 Certificate Chain Presented',
            payloadPreview: 'Certificate: CN=mail.legacy-corp.example.com, RSA 2048-bit',
            detail: 'Server transmits X.509 leaf certificate.',
            packetNumber: 36,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-10',
            timestamp: '10:01:02.490',
            relativeMs: 350,
            direction: 'CLIENT_TO_SERVER',
            stage: 'TLS_HANDSHAKE',
            title: 'Client Key Exchange: Static RSA Encrypted Pre-Master Secret',
            payloadPreview: 'Handshake Type: Client Key Exchange (16), EncryptedPreMasterSecret [256 bytes]',
            isWeaknessOrAnomaly: true,
            detail: 'Static RSA key exchange observed. No ephemeral Diffie-Hellman parameters exchanged. Forward secrecy is NOT achieved.',
            packetNumber: 42,
            tcpStreamIndex: 3
          },
          {
            id: 'EVT-11',
            timestamp: '10:01:02.580',
            relativeMs: 440,
            direction: 'INTERNAL',
            stage: 'TLS_HANDSHAKE',
            title: 'TLS Handshake Completed (Finished / Encrypted Handshake Message)',
            detail: 'TLS session established over deprecated cryptographic profile.',
            packetNumber: 48,
            tcpStreamIndex: 3
          }
        ]
      },
      {
        id: 'SES-015',
        pcapId: 'PCAP-2026-002',
        protocol: 'SMTP',
        sourceIp: '198.51.100.99',
        sourcePort: 54110,
        destIp: '203.0.113.25',
        destPort: 25,
        serverHostname: 'mail.legacy-corp.example.com',
        startTlsAdvertised: true,
        startTlsRequested: true,
        startTlsNegotiated: true,
        risk: 'HIGH',
        evidenceConfidence: 'COMPLETE',
        evidenceConfidenceReason: 'Reconstructed TCP stream with full TLS negotiation.',
        durationSec: 3.12,
        timestamp: '2026-09-24 10:01:14.300 UTC',
        findingsIds: ['FIND-014', 'FIND-016'],
        evidenceIds: ['EVD-014-TLS', 'EVD-014-PFS'],
        bannerText: '220 mail.legacy-corp.example.com Microsoft ESMTP MAIL Service ready',
        tlsHandshake: {
          negotiatedVersion: 'TLS 1.0',
          isDeprecatedVersion: true,
          cipherSuite: {
            ianaName: 'TLS_RSA_WITH_AES_128_CBC_SHA',
            rfcCode: '0x002F',
            keyExchange: 'RSA (Static)',
            encryption: 'AES-128-CBC',
            mac: 'HMAC-SHA1',
            forwardSecrecy: false,
            isWeak: true,
            weaknessReason: 'CBC-mode padding oracle vulnerability; lacks Forward Secrecy.'
          },
          forwardSecrecy: false
        },
        protocolEvents: []
      }
    ],
    findings: [
      {
        id: 'FIND-014',
        title: 'Deprecated TLS Version Observed (TLS 1.0)',
        severity: 'HIGH',
        confidence: 'COMPLETE',
        evidenceClass: 'ASSESSED',
        observedValue: 'TLS 1.0 (Record 0x0301, Server Hello in packet #34)',
        expectedPolicyValue: 'TLS 1.2+ with approved AEAD / TLS 1.3 preferred under SecureMailScope Email TLS Baseline',
        policyProfile: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
        affectedSessionId: 'SES-014',
        evidenceIds: ['EVD-014-TLS'],
        ruleId: 'RULE-TLS-001',
        ruleTitle: 'Deprecated TLS Protocol Version Policy',
        standardReference: 'RFC 8996 (BCP 195) & RFC 9325 / NIST SP 800-52r2',
        evidenceStatement: 'Server Hello record in TCP packet 34 negotiated protocol version 0x0301 (TLS 1.0). Full handshake recorded in PCAP.',
        technicalReason: 'TLS 1.0 was formally retired by IETF RFC 8996 in March 2021. It relies on obsolete cipher modes, vulnerable MAC algorithms, and lacks protection against modern cryptanalytic attacks. Current BCP 195 guidance (RFC 9325) mandates TLS 1.2 or TLS 1.3.',
        securityImpact: 'Legacy TLS versions fail modern compliance audits (PCI-DSS 3.1+, HIPAA, NIST). Active network adversaries can trigger downgrade attacks against connecting clients.',
        recommendedAction: 'Reconfigure MTA TLS parameters to disable TLS 1.0 and TLS 1.1 completely. Require minimum protocol version TLS 1.2 with AEAD, or preferably TLS 1.3 (RFC 9846).',
        priorityOrder: 1,
        remediationComplexity: 'LOW',
        status: 'OPEN',
        forensicLimitations: 'Deterministic observation applies specifically to captured sessions SES-014 and SES-015.'
      },
      {
        id: 'FIND-015',
        title: '3DES / 64-bit Block Cipher Detected',
        severity: 'HIGH',
        confidence: 'COMPLETE',
        evidenceClass: 'ASSESSED',
        observedValue: 'Cipher suite 0x000A (TLS_RSA_WITH_3DES_EDE_CBC_SHA) negotiated in Server Hello (Packet 34)',
        expectedPolicyValue: 'AEAD Cipher (AES-GCM or ChaCha20-Poly1305) with >=128-bit key size',
        policyProfile: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
        affectedSessionId: 'SES-014',
        evidenceIds: ['EVD-014-CIPHER'],
        ruleId: 'RULE-CIPHER-002',
        ruleTitle: 'Obsolete Block Cipher Suite Prohibition (3DES / RC4 / DES)',
        standardReference: 'RFC 9325 Section 4.2 / RFC 8996 Section 2 / CVE-2016-2183 / NIST SP 800-131Ar2',
        evidenceStatement: 'Cipher suite field 0x000A observed in Server Hello (Packet 34). Effective symmetric key size 112 bits with 64-bit block size.',
        technicalReason: 'Triple-DES uses a 64-bit block cipher structure vulnerable to birthday attacks (Sweet32, CVE-2016-2183). An eavesdropper monitoring a continuous session can recover plaintext blocks after approximately 2^32 blocks (32GB) of encrypted traffic. (Note: The application detected the cryptographic condition; it did not observe an active Sweet32 exploitation attempt).',
        securityImpact: 'Symmetric confidentiality exposure under prolonged session conditions. Disallowed by modern compliance frameworks and RFC 9325 Section 4.2.',
        recommendedAction: 'Remove 3DES (DES-CBC3-SHA) from the server cipher suite string in Postfix/Exchange/Exim. Enforce modern AEAD ciphers (AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305).',
        priorityOrder: 2,
        remediationComplexity: 'LOW',
        status: 'OPEN',
        forensicLimitations: 'Evaluated from reconstructed Server Hello record; 0 bytes of traffic decryption observed.'
      },
      {
        id: 'FIND-016',
        title: 'No Forward Secrecy — Static RSA Key Exchange',
        severity: 'HIGH',
        confidence: 'COMPLETE',
        evidenceClass: 'ASSESSED',
        observedValue: 'Client Key Exchange contained RSA EncryptedPreMasterSecret (Packet 42); no Ephemeral Diffie-Hellman parameters negotiated',
        expectedPolicyValue: 'Ephemeral Key Exchange (ECDHE/DHE) providing Perfect Forward Secrecy',
        policyProfile: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
        affectedSessionId: 'SES-014',
        evidenceIds: ['EVD-014-PFS'],
        ruleId: 'RULE-CIPHER-003',
        ruleTitle: 'Ephemeral Key Exchange Mandate (Forward Secrecy Enforcement)',
        standardReference: 'RFC 9325 Section 4.1 (BCP 195) / NIST SP 800-52r2 Section 3.3.1 / BSI TR-02102-2',
        evidenceStatement: 'Client Key Exchange message in Packet 42 contained an RSA-encrypted pre-master secret rather than ECDHE/DHE parameters.',
        technicalReason: 'Static RSA key exchange directly encrypts the session key using the server public key. Because no ephemeral Diffie-Hellman keys are used, forward secrecy is not provided. If the long-term server private key is later compromised, previously captured sessions may be susceptible to retrospective decryption, subject to the captured handshake and session conditions. (Note: PCAP evidence does not indicate that private key compromise or traffic decryption occurred).',
        securityImpact: 'Retrospective confidentiality risk in the event of future server private key compromise.',
        recommendedAction: 'Restrict acceptable cipher suites to ephemeral ECDHE key exchange (e.g. ECDHE-ECDSA or ECDHE-RSA). Disable static RSA key exchange algorithms.',
        priorityOrder: 3,
        remediationComplexity: 'LOW',
        status: 'OPEN',
        forensicLimitations: 'Structural key exchange assessment; no attacker private key compromise observed in PCAP.'
      }
    ],
    evidenceList: [
      {
        id: 'EVD-014-TLS',
        sessionId: 'SES-014',
        pcapId: 'PCAP-2026-002',
        evidenceType: 'TLS_VERSION',
        rawObservation: 'TLS Handshake: Server Hello (Packet #34), Version: 0x0301 (TLS 1.0)',
        packetFrameNumbers: [30, 34],
        byteOffsetHex: '0x0000015A',
        hexDumpSample: '16 03 01 00 4a 02 00 00 46 03 01 64 21 0a 91 a4 77 12 ... 00 0a 00',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Both Client Hello and Server Hello packets captured intact with matching TCP sequence numbers and valid checksums.',
        verifiedTimestamp: '2026-09-24 10:01:02.385 UTC',
        authoritativeStandard: 'RFC 8996 (BCP 195)'
      },
      {
        id: 'EVD-014-CIPHER',
        sessionId: 'SES-014',
        pcapId: 'PCAP-2026-002',
        evidenceType: 'CIPHER_SUITE',
        rawObservation: 'Cipher Suite selected: 0x000A (TLS_RSA_WITH_3DES_EDE_CBC_SHA)',
        packetFrameNumbers: [34],
        byteOffsetHex: '0x00000188',
        hexDumpSample: '00 0a 00 00 1a 00 17 00 00 00 00 00 00 00 ...',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Explicit 2-byte IANA cipher code decoded from Server Hello payload.',
        verifiedTimestamp: '2026-09-24 10:01:02.385 UTC',
        authoritativeStandard: 'CVE-2016-2183'
      },
      {
        id: 'EVD-014-PFS',
        sessionId: 'SES-014',
        pcapId: 'PCAP-2026-002',
        evidenceType: 'KEY_EXCHANGE',
        rawObservation: 'Client Key Exchange message (Packet #42) type 16 (EncryptedPreMasterSecret)',
        packetFrameNumbers: [42],
        byteOffsetHex: '0x0000021C',
        hexDumpSample: '16 03 01 01 04 10 00 01 00 8f a3 99 10 44 ...',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Inspection of packet 42 confirms static RSA exchange without Diffie-Hellman ServerKeyExchange (type 12) frame.',
        verifiedTimestamp: '2026-09-24 10:01:02.490 UTC',
        authoritativeStandard: 'NIST SP 800-52r2'
      },
      {
        id: 'EVD-014-CERT',
        sessionId: 'SES-014',
        pcapId: 'PCAP-2026-002',
        evidenceType: 'CERTIFICATE',
        rawObservation: 'X.509 Certificate Presented: CN=mail.legacy-corp.example.com, RSA 2048-bit, Valid until March 2027',
        packetFrameNumbers: [36],
        byteOffsetHex: '0x000001DC',
        hexDumpSample: '30 82 04 88 30 82 03 70 a0 03 02 01 02 02 08 3a 89 1f b2 ...',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Full DER-encoded X.509 certificate parsed from TLS Certificate message (Handshake type 11).',
        verifiedTimestamp: '2026-09-24 10:01:02.420 UTC',
        authoritativeStandard: 'RFC 5280'
      }
    ],
    rules: DETERMINISTIC_RULES
  },

  // SCENARIO 3: Certificate Problem (Expired Cert on IMAP)
  {
    id: 'scenario-expired-cert',
    title: 'Scenario 3: Expired Certificate & Weak Hash on IMAP',
    subtitle: 'IMAP Port 993 · Direct TLS 1.2 · Expired 42 Days · SHA-1 Signature',
    description: 'Corporate IMAP service running with an expired X.509 certificate and legacy SHA-1 signature algorithm, breaking transport trust and client validation.',
    defaultSelectedSessionId: 'SES-003',
    pcapMetadata: {
      id: 'PCAP-2026-003',
      filename: 'corp_imap_expired_cert_sha1.pcapng',
      sha256: '4c891b01fa288190de12348576ab01289cf001192837465019a8273645109823',
      fileSizeBytes: 1248000,
      captureTimestamp: '2026-09-24 11:15:00 UTC',
      analysisTimestamp: '2026-09-24 11:16:30 UTC',
      packetCount: 680,
      streamCount: 4,
      status: 'VERIFIED',
      confidence: 'COMPLETE',
      capturedInterface: 'vlan102-mirror',
      notes: 'Captured at core internal router mirror.',
      sha256VerificationState: 'COMPUTED',
      captureDurationSec: 6.2,
      totalTcpFlows: 4,
      completeSessionsCount: 1,
      partialSessionsCount: 0,
      truncatedSessionsCount: 0,
      tlsHandshakeCount: 1,
      truncatedHandshakeCount: 0,
      missingPacketsCount: 0
    },
    sessions: [
      {
        id: 'SES-003',
        pcapId: 'PCAP-2026-003',
        protocol: 'IMAP',
        sourceIp: '10.20.4.88',
        sourcePort: 58210,
        destIp: '10.20.0.10',
        destPort: 993,
        serverHostname: 'imap.internal.corp',
        startTlsAdvertised: false,
        startTlsRequested: false,
        startTlsNegotiated: true,
        risk: 'HIGH',
        evidenceConfidence: 'COMPLETE',
        evidenceConfidenceReason: 'Direct TLS connection on port 993 with complete certificate chain payload.',
        durationSec: 6.2,
        timestamp: '2026-09-24 11:15:00.080 UTC',
        findingsIds: ['FIND-021', 'FIND-022'],
        evidenceIds: ['EVD-021-CERT-EXP', 'EVD-022-CERT-SHA1'],
        bannerText: '* OK [CAPABILITY IMAP4rev1 SASL-IR LITERAL+ ID ENABLE] Dovecot ready.',
        tlsHandshake: {
          negotiatedVersion: 'TLS 1.2',
          isDeprecatedVersion: false,
          cipherSuite: {
            ianaName: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            rfcCode: '0xC02F',
            keyExchange: 'ECDHE (secp256r1)',
            encryption: 'AES-128-GCM',
            mac: 'AEAD',
            forwardSecrecy: true,
            isWeak: false
          },
          forwardSecrecy: true,
          certificate: {
            serialNumber: '11:22:33:44:AA:BB:CC:DD',
            subject: 'CN=imap.internal.corp, OU=IT Infrastructure, O=Enterprise Inc, C=US',
            subjectCommonName: 'imap.internal.corp',
            issuer: 'CN=Enterprise Legacy Intermediate CA, O=Enterprise Inc, C=US',
            issuerCommonName: 'Enterprise Legacy Intermediate CA',
            validFrom: '2024-08-10 00:00:00 UTC',
            validUntil: '2026-08-12 23:59:59 UTC',
            isExpired: true,
            daysUntilExpiry: -42,
            publicKeyAlgorithm: 'RSA',
            keyLengthBits: 2048,
            signatureAlgorithm: 'sha1WithRSAEncryption',
            isWeakKey: false,
            isWeakSignature: true,
            chainStatus: 'EXPIRED',
            sanList: ['imap.internal.corp', 'mail.internal.corp'],
            fingerprintSha256: 'FA:88:21:49:10:CC:01:88:99:A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:12:34:56:78:9A:BC:DE'
          },
          handshakeMessages: [
            { name: 'ClientHello', stage: 'TLS_HANDSHAKE', frameNumber: 4, status: 'OBSERVED', description: 'TLS 1.2 Client Hello (IMAPS Port 993)' },
            { name: 'ServerHello', stage: 'TLS_HANDSHAKE', frameNumber: 6, status: 'OBSERVED', description: 'Selected TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256' },
            { name: 'Certificate', stage: 'TLS_HANDSHAKE', frameNumber: 8, status: 'OBSERVED', description: 'Presented expired X.509 certificate with SHA-1 signature' },
            { name: 'ServerKeyExchange', stage: 'TLS_HANDSHAKE', frameNumber: 8, status: 'OBSERVED', description: 'ECDH secp256r1 parameters and server signature' },
            { name: 'ServerHelloDone', stage: 'TLS_HANDSHAKE', frameNumber: 8, status: 'OBSERVED', description: 'Server completed handshake turn' },
            { name: 'ClientKeyExchange', stage: 'TLS_HANDSHAKE', frameNumber: 10, status: 'OBSERVED', description: 'Client ECDH public key share' },
            { name: 'Finished', stage: 'TLS_HANDSHAKE', frameNumber: 12, status: 'OBSERVED', description: 'Encrypted Finished record validating handshake integrity' }
          ]
        },
        protocolEvents: [
          {
            id: 'EVT-I01',
            timestamp: '11:15:00.080',
            relativeMs: 0,
            direction: 'INTERNAL',
            stage: 'TCP',
            title: 'TCP Handshake (IMAPS Port 993)',
            detail: 'Direct TLS connection initiated.',
            packetNumber: 2,
            tcpStreamIndex: 1
          },
          {
            id: 'EVT-I02',
            timestamp: '11:15:00.120',
            relativeMs: 40,
            direction: 'SERVER_TO_CLIENT',
            stage: 'TLS_HANDSHAKE',
            title: 'Server Certificate Presented (Expired & Weak Hash)',
            payloadPreview: 'Certificate: CN=imap.internal.corp, NotAfter: 2026-08-12 (Expired), SigAlgo: sha1WithRSAEncryption',
            isWeaknessOrAnomaly: true,
            detail: 'CRITICAL FORENSIC OBSERVATION: Certificate validity lapsed 42 days ago; signature relies on deprecated SHA-1.',
            packetNumber: 8,
            tcpStreamIndex: 1
          }
        ]
      }
    ],
    findings: [
      {
        id: 'FIND-021',
        title: 'Expired X.509 Certificate Presented in TLS Handshake',
        severity: 'HIGH',
        confidence: 'COMPLETE',
        evidenceClass: 'ASSESSED',
        observedValue: 'notAfter timestamp: 2026-08-12 23:59:59 UTC (Expired 42 days prior to capture timestamp 2026-09-24)',
        expectedPolicyValue: 'Current timestamp within validity window (notBefore <= now <= notAfter)',
        policyProfile: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
        affectedSessionId: 'SES-003',
        evidenceIds: ['EVD-021-CERT-EXP'],
        ruleId: 'RULE-CERT-001',
        ruleTitle: 'X.509 Certificate Validity Period & Expiry Enforcement',
        standardReference: 'RFC 5280 Section 4.1.2.5 / CAB Forum BR 7.1.4',
        evidenceStatement: 'Certificate validity end date (notAfter) observed in Packet 8 was 2026-08-12 23:59:59 UTC. Capture timestamp is 2026-09-24 (42 days past expiry).',
        technicalReason: 'Expired certificates fail RFC 5280 Section 4.1.2.5 validity verification. Remote mail clients cannot establish cryptographic trust, exposing connections to active Man-in-the-Middle impersonation. Note: Certificate chain was observed in the handshake; local trust store validation was not performed by the passive analyzer.',
        securityImpact: 'MitM Vulnerability: When end-users grow accustomed to clicking past certificate warnings, active attackers can insert proxy interception nodes without raising alarm.',
        recommendedAction: 'Immediately issue and deploy a renewed X.509 certificate for imap.internal.corp with automated renewal (ACME / cert-manager).',
        priorityOrder: 1,
        remediationComplexity: 'LOW',
        status: 'OPEN',
        forensicLimitations: 'Certificate chain observed in wire handshake frame #8; external CA root store verification not performed.'
      },
      {
        id: 'FIND-022',
        title: 'Deprecated SHA-1 Signature Algorithm in Certificate Chain',
        severity: 'HIGH',
        confidence: 'COMPLETE',
        evidenceClass: 'ASSESSED',
        observedValue: 'signatureAlgorithm OID: 1.2.840.113549.1.1.5 (sha1WithRSAEncryption)',
        expectedPolicyValue: 'sha256WithRSAEncryption or stronger (CAB Forum BR 7.1.3)',
        policyProfile: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
        affectedSessionId: 'SES-003',
        evidenceIds: ['EVD-022-CERT-SHA1'],
        ruleId: 'RULE-CERT-004',
        ruleTitle: 'Deprecated Weak Hash Algorithm in X.509 Signature (SHA-1 / MD5)',
        standardReference: 'RFC 9325 Section 4.3 / NIST Policy on SHA-1 Deprecation / CAB Forum BR 7.1.3',
        evidenceStatement: 'Certificate signatureAlgorithm ASN.1 OID 1.2.840.113549.1.1.5 (sha1WithRSAEncryption) decoded in certificate structure.',
        technicalReason: 'SHA-1 collision attacks have been demonstrated practically since 2017 (SHAttered attack). Deprecated by RFC 9325 Section 4.3 and disallowed by CA/Browser Forum Baseline Requirements Section 7.1.3.',
        securityImpact: 'Cryptographic spoofing risk. Rejected by standard OS trust stores including Windows, macOS, Android, and modern OpenSSL configurations.',
        recommendedAction: 'Re-sign all issued internal certificates using SHA-256 (sha256WithRSAEncryption) or SHA-384.',
        priorityOrder: 2,
        remediationComplexity: 'MEDIUM',
        status: 'OPEN',
        forensicLimitations: 'Directly parsed from ASN.1 TBSCertificate and outer signature block.'
      }
    ],
    evidenceList: [
      {
        id: 'EVD-021-CERT-EXP',
        sessionId: 'SES-003',
        pcapId: 'PCAP-2026-003',
        evidenceType: 'CERTIFICATE',
        rawObservation: 'Certificate notAfter timestamp: 2026-08-12 23:59:59 UTC. Capture timestamp: 2026-09-24 11:15:00 UTC.',
        packetFrameNumbers: [8],
        byteOffsetHex: '0x00000140',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Validity period ASN.1 UTCTime decoded directly from Certificate structure.',
        verifiedTimestamp: '2026-09-24 11:15:00.120 UTC',
        authoritativeStandard: 'RFC 5280'
      },
      {
        id: 'EVD-022-CERT-SHA1',
        sessionId: 'SES-003',
        pcapId: 'PCAP-2026-003',
        evidenceType: 'CERTIFICATE',
        rawObservation: 'signatureAlgorithm OID: 1.2.840.113549.1.1.5 (sha1WithRSAEncryption)',
        packetFrameNumbers: [8],
        byteOffsetHex: '0x0000012A',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Signature algorithm identifier decoded in TBSCertificate and outer signature block.',
        verifiedTimestamp: '2026-09-24 11:15:00.120 UTC',
        authoritativeStandard: 'NIST SP 800-131Ar2'
      }
    ],
    rules: DETERMINISTIC_RULES
  },

  // SCENARIO 4: Plaintext POP3 (Cleartext Authentication Exposure)
  {
    id: 'scenario-plaintext-pop3',
    title: 'Scenario 4: Plaintext POP3 Credentials Exposure',
    subtitle: 'POP3 Port 110 · Cleartext USER/PASS · No TLS · RFC 8314 Breach',
    description: 'Completely unencrypted POP3 session on port 110 transmitting corporate user mailbox credentials in cleartext over the local network segment.',
    defaultSelectedSessionId: 'SES-004',
    pcapMetadata: {
      id: 'PCAP-2026-004',
      filename: 'legacy_pop3_cleartext_auth_exposure.pcapng',
      sha256: '11e89b21fa70029bca1188339485710294857102938475610293847561029384',
      fileSizeBytes: 492000,
      captureTimestamp: '2026-09-24 14:02:10 UTC',
      analysisTimestamp: '2026-09-24 14:03:00 UTC',
      packetCount: 210,
      streamCount: 2,
      status: 'VERIFIED',
      confidence: 'COMPLETE',
      capturedInterface: 'eth1 (Office LAN Gateway)',
      notes: 'Captured via switch port monitor. Contains plaintext application layer commands.',
      sha256VerificationState: 'COMPUTED',
      captureDurationSec: 1.85,
      totalTcpFlows: 2,
      completeSessionsCount: 1,
      partialSessionsCount: 0,
      truncatedSessionsCount: 0,
      tlsHandshakeCount: 0,
      truncatedHandshakeCount: 0,
      missingPacketsCount: 0
    },
    sessions: [
      {
        id: 'SES-004',
        pcapId: 'PCAP-2026-004',
        protocol: 'POP3',
        sourceIp: '192.168.1.105',
        sourcePort: 52199,
        destIp: '192.168.1.5',
        destPort: 110,
        serverHostname: 'pop3.finance-internal.org',
        startTlsAdvertised: false,
        startTlsRequested: false,
        startTlsNegotiated: false,
        risk: 'CRITICAL',
        evidenceConfidence: 'COMPLETE',
        evidenceConfidenceReason: 'Unencrypted ASCII protocol stream captured in full, including command verbs and arguments.',
        durationSec: 1.85,
        timestamp: '2026-09-24 14:02:10.012 UTC',
        findingsIds: ['FIND-031'],
        evidenceIds: ['EVD-031-PLAINTEXT-AUTH'],
        bannerText: '+OK POP3 server ready (Finance Department Mail Service)',
        plaintextCredentialsExposed: true,
        protocolEvents: [
          {
            id: 'EVT-P01',
            timestamp: '14:02:10.012',
            relativeMs: 0,
            direction: 'INTERNAL',
            stage: 'TCP',
            title: 'TCP Connection Established (Port 110 Plaintext)',
            detail: 'Client connected to standard unencrypted POP3 port.',
            packetNumber: 2,
            tcpStreamIndex: 0
          },
          {
            id: 'EVT-P02',
            timestamp: '14:02:10.035',
            relativeMs: 23,
            direction: 'SERVER_TO_CLIENT',
            stage: 'BANNER',
            title: 'POP3 Ready Banner',
            payloadPreview: '+OK POP3 server ready (Finance Department Mail Service)',
            detail: 'Server responds in cleartext.',
            packetNumber: 4,
            tcpStreamIndex: 0
          },
          {
            id: 'EVT-P03',
            timestamp: '14:02:10.070',
            relativeMs: 58,
            direction: 'CLIENT_TO_SERVER',
            stage: 'AUTH',
            title: 'Cleartext USER Command Transmitted',
            payloadPreview: 'USER j.smith@finance-internal.org',
            isWeaknessOrAnomaly: true,
            detail: 'CRITICAL FORENSIC OBSERVATION: Mailbox username transmitted across network in unencrypted ASCII.',
            packetNumber: 6,
            tcpStreamIndex: 0
          },
          {
            id: 'EVT-P04',
            timestamp: '14:02:10.110',
            relativeMs: 98,
            direction: 'CLIENT_TO_SERVER',
            stage: 'AUTH',
            title: 'Cleartext PASS Command Transmitted',
            payloadPreview: 'PASS [CONFIDENTIAL_CREDENTIAL_OBSERVED_IN_PCAP]',
            isWeaknessOrAnomaly: true,
            detail: 'CRITICAL FORENSIC OBSERVATION: Raw password transmitted in cleartext. Any passive network listener can harvest this credential.',
            packetNumber: 8,
            tcpStreamIndex: 0
          },
          {
            id: 'EVT-P05',
            timestamp: '14:02:10.145',
            relativeMs: 133,
            direction: 'SERVER_TO_CLIENT',
            stage: 'AUTH',
            title: 'Server Confirms Authentication (+OK Mailbox locked and ready)',
            payloadPreview: '+OK Mailbox locked and ready (42 messages)',
            detail: 'Authentication succeeds without cryptographic protection.',
            packetNumber: 10,
            tcpStreamIndex: 0
          }
        ]
      }
    ],
    findings: [
      {
        id: 'FIND-031',
        title: 'Cleartext POP3 Protocol with Authentication Credentials Exposed',
        severity: 'CRITICAL',
        confidence: 'COMPLETE',
        evidenceClass: 'OBSERVED',
        observedValue: 'Cleartext ASCII commands: USER j.smith@finance-internal.org, PASS [CONFIDENTIAL] (Packets #6 & #8)',
        expectedPolicyValue: 'Encapsulated TLS on Port 995 (POP3S) or STLS per RFC 8314 Section 3',
        policyProfile: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
        affectedSessionId: 'SES-004',
        evidenceIds: ['EVD-031-PLAINTEXT-AUTH'],
        ruleId: 'RULE-PLAIN-001',
        ruleTitle: 'Cleartext Mail Protocol Transport & Credential Exposure',
        standardReference: 'RFC 8314 Section 3 (Cleartext Considered Obsolete for Email Submission and Access)',
        evidenceStatement: 'TCP port 110 stream 0 contained plain ASCII commands USER and PASS without any TLS layer or STLS negotiation.',
        technicalReason: 'RFC 8314 declares cleartext mail protocols obsolete. Using plaintext authentication sends usernames and passwords unhashed over local Wi-Fi, Ethernet, and routing nodes.',
        securityImpact: 'Immediate account compromise. Passwords harvested passively can be reused by threat actors for lateral movement into corporate systems and data exfiltration.',
        recommendedAction: 'Immediately shut down unencrypted POP3 on port 110. Migrate all clients to POP3S on port 995 with mandatory TLS 1.2/1.3, or deprecate POP3 in favor of Modern Auth IMAP/OAuth2.',
        priorityOrder: 1,
        remediationComplexity: 'HIGH',
        status: 'OPEN',
        forensicLimitations: 'Directly observed in unencrypted TCP payload of session SES-004.'
      }
    ],
    evidenceList: [
      {
        id: 'EVD-031-PLAINTEXT-AUTH',
        sessionId: 'SES-004',
        pcapId: 'PCAP-2026-004',
        evidenceType: 'PLAINTEXT_EXPOSURE',
        rawObservation: 'Cleartext USER and PASS commands identified in TCP stream 0 payload (Packets 6 & 8)',
        packetFrameNumbers: [6, 8],
        byteOffsetHex: '0x00000042',
        hexDumpSample: '55 53 45 52 20 6a 2e 73 6d 69 74 68 40 ... 50 41 53 53 20 ... 0d 0a',
        confidence: 'COMPLETE',
        confidenceExplanation: 'Cleartext ASCII strings extracted directly from TCP payload; no encryption layer present.',
        verifiedTimestamp: '2026-09-24 14:02:10.070 UTC',
        authoritativeStandard: 'RFC 8314'
      }
    ],
    rules: DETERMINISTIC_RULES
  },

  // SCENARIO 5: Incomplete PCAP (Demonstrates Evidence Confidence & Humility)
  {
    id: 'scenario-incomplete-pcap',
    title: 'Scenario 5: Truncated Incomplete SMTP Capture',
    subtitle: 'SMTP Port 25 · Truncated TCP Stream · Incomplete Handshake · Confidence: INSUFFICIENT',
    description: 'Real-world scenario where packet capture was cut off prematurely during upstream switch buffer saturation, illustrating that SecureMailScope never hallucinates certainty.',
    defaultSelectedSessionId: 'SES-005',
    pcapMetadata: {
      id: 'PCAP-2026-005',
      filename: 'upstream_tap_truncated_buffer_drop.pcapng',
      sha256: '99887766554433221100aabbccddeeff00112233445566778899aabbccddeeff',
      fileSizeBytes: 84200,
      captureTimestamp: '2026-09-24 16:45:00 UTC',
      analysisTimestamp: '2026-09-24 16:46:10 UTC',
      packetCount: 19,
      streamCount: 1,
      status: 'VERIFIED',
      confidence: 'INSUFFICIENT',
      confidenceReason: 'Packet capture buffer terminated mid-handshake. Server Hello and X.509 Certificate packets are absent from the trace.',
      capturedInterface: 'tap0 (Saturated Tap Buffer)',
      notes: 'Truncated PCAP. Demonstrates strict evidence confidence gating.',
      sha256VerificationState: 'COMPUTED',
      captureDurationSec: 0.42,
      totalTcpFlows: 1,
      completeSessionsCount: 0,
      partialSessionsCount: 1,
      truncatedSessionsCount: 1,
      tlsHandshakeCount: 0,
      truncatedHandshakeCount: 1,
      missingPacketsCount: 4
    },
    sessions: [
      {
        id: 'SES-005',
        pcapId: 'PCAP-2026-005',
        protocol: 'SMTP',
        sourceIp: '198.51.100.80',
        sourcePort: 43100,
        destIp: '203.0.113.100',
        destPort: 25,
        serverHostname: 'mx1.upstream-gateway.net',
        startTlsAdvertised: true,
        startTlsRequested: true,
        startTlsNegotiated: false,
        risk: 'MEDIUM',
        evidenceConfidence: 'INSUFFICIENT',
        evidenceConfidenceReason: 'TCP stream contains STARTTLS request and Client Hello (Packet 12), but the capture abruptly ends prior to Server Hello. Certificate and negotiated cipher cannot be reliably deduced.',
        durationSec: 0.42,
        timestamp: '2026-09-24 16:45:00.100 UTC',
        findingsIds: ['FIND-041'],
        evidenceIds: ['EVD-041-TRUNCATED'],
        bannerText: '220 mx1.upstream-gateway.net ESMTP Sendmail ready',
        protocolEvents: [
          {
            id: 'EVT-T01',
            timestamp: '16:45:00.100',
            relativeMs: 0,
            direction: 'INTERNAL',
            stage: 'TCP',
            title: 'TCP Handshake Initiated',
            detail: 'SYN, SYN/ACK, ACK captured.',
            packetNumber: 1,
            tcpStreamIndex: 0
          },
          {
            id: 'EVT-T02',
            timestamp: '16:45:00.140',
            relativeMs: 40,
            direction: 'SERVER_TO_CLIENT',
            stage: 'BANNER',
            title: 'SMTP Banner & STARTTLS Advertised',
            payloadPreview: '220 mx1.upstream-gateway.net ESMTP Sendmail ready\n250-STARTTLS',
            detail: 'Server advertises STARTTLS.',
            packetNumber: 5,
            tcpStreamIndex: 0
          },
          {
            id: 'EVT-T03',
            timestamp: '16:45:00.190',
            relativeMs: 90,
            direction: 'CLIENT_TO_SERVER',
            stage: 'TLS_HANDSHAKE',
            title: 'TLS Client Hello Transmitted',
            payloadPreview: 'TLS Record: Handshake (Client Hello)',
            detail: 'Client offers cipher suites. CAPTURE ENDS HERE.',
            packetNumber: 12,
            tcpStreamIndex: 0
          },
          {
            id: 'EVT-T04',
            timestamp: '16:45:00.220',
            relativeMs: 120,
            direction: 'INTERNAL',
            stage: 'TERMINATION',
            title: 'Premature End of Capture (Truncation)',
            isWeaknessOrAnomaly: true,
            detail: 'Zero subsequent packets captured. Server response missing from PCAP file.',
            packetNumber: 13,
            tcpStreamIndex: 0
          }
        ]
      }
    ],
    findings: [
      {
        id: 'FIND-041',
        title: 'Incomplete TLS Handshake Observation (Forensic Evidence Truncation)',
        severity: 'MEDIUM',
        confidence: 'INSUFFICIENT',
        evidenceClass: 'OBSERVED',
        observedValue: 'Client Hello in Packet #12; capture terminates at packet #14 before Server Hello',
        expectedPolicyValue: 'Complete bidirectional TLS handshake records',
        policyProfile: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
        affectedSessionId: 'SES-005',
        evidenceIds: ['EVD-041-TRUNCATED'],
        ruleId: 'RULE-PCAP-009',
        ruleTitle: 'Observation Truncation & Insufficient Packet Capture Window',
        standardReference: 'ISO/IEC 27037:2012 (Digital Evidence Forensic Completeness)',
        evidenceStatement: 'Client Hello was observed in Packet 12, but Server Hello and Certificate messages are missing due to PCAP trace truncation.',
        technicalReason: 'Deterministic cryptographic posture evaluation requires observing both sides of the handshake negotiation. Without the Server Hello, the final negotiated version, cipher suite, and certificate chain cannot be mathematically established. Under ISO/IEC 27037 digital forensic completeness guidelines, conclusions are conservatively withheld.',
        securityImpact: 'Potential blind spot: Traffic may or may not have proceeded with strong cryptography; assessment remains indeterminate.',
        recommendedAction: 'Re-capture traffic on this link ensuring sufficient ring buffer allocation and zero dropped packets (e.g. verify ifconfig drop counters or ethtool rx_dropped).',
        priorityOrder: 1,
        remediationComplexity: 'MEDIUM',
        status: 'OPEN',
        forensicLimitations: 'Observation truncated due to switch tap buffer saturation; cryptographic profile indeterminate.'
      }
    ],
    evidenceList: [
      {
        id: 'EVD-041-TRUNCATED',
        sessionId: 'SES-005',
        pcapId: 'PCAP-2026-005',
        evidenceType: 'TLS_VERSION',
        rawObservation: 'TLS Client Hello observed (Packet #12) without corresponding Server Hello',
        packetFrameNumbers: [12],
        byteOffsetHex: '0x0000007A',
        confidence: 'INSUFFICIENT',
        confidenceExplanation: 'TCP FIN/RST or subsequent data segments missing. Capture ended prematurely.',
        verifiedTimestamp: '2026-09-24 16:45:00.190 UTC',
        authoritativeStandard: 'ISO/IEC 27037'
      }
    ],
    rules: DETERMINISTIC_RULES
  },
  // SCENARIO 6: Out-of-Scope Vehicular Telemetry (ITS-G5 / V2X)
  {
    id: 'scenario-itsg5-vehicular',
    title: 'Scenario 6: Out-of-Scope Vehicular Telemetry (ITS-G5 / V2X)',
    subtitle: '5,313 Packets · ETSI ITS-G5 CAM/DENM · 0 Email Streams · Assessment Out of Scope',
    description: 'Real-world connected vehicle broadcast trace (ETSI GeoNetworking, CAM, DENM over 5.9 GHz DSRC/C-V2X). Protocol Classification Engine identifies 100% vehicular telemetry; Scope Validation Layer halts email assessment and diverts to V2X Security Gateway with NOT ASSESSABLE status.',
    defaultSelectedSessionId: '',
    pcapMetadata: {
      id: 'PCAP-2026-V2X-01',
      filename: 'connected_corridor_its_g5_v2x.pcapng',
      sha256: '4f89d31a57b28c3014de99824c96571a8e24bf98a723812d6a59cb4a148f95c2',
      fileSizeBytes: 2481020,
      captureTimestamp: '2026-09-25 11:20:00 UTC',
      analysisTimestamp: '2026-09-25 11:20:45 UTC',
      packetCount: 5313,
      streamCount: 0,
      status: 'VERIFIED',
      confidence: 'COMPLETE',
      capturedInterface: 'wlan0 (ETSI ITS-G5 Roadside Unit TAP)',
      notes: 'Automotive vehicular telemetry capture. Zero email traffic present.',
      captureDurationSec: 60.0,
      totalTcpFlows: 0,
      tlsHandshakeCount: 0,
      protocolClassification: {
        detectedProtocols: [
          { protocol: 'ITS-G5', packetCount: 5313, percentage: 100, category: 'VEHICULAR' }
        ],
        counts: {
          smtp: 0,
          smtps: 0,
          imap: 0,
          imaps: 0,
          pop3: 0,
          pop3s: 0,
          http: 0,
          https: 0,
          dns: 0,
          ssh: 0,
          ftp: 0,
          icmp: 0,
          itsG5: 5313,
          v2x: 0,
          unknown: 0
        },
        totalEmailPackets: 0,
        totalNonEmailPackets: 5313,
        primaryProtocol: 'ITS-G5',
        primaryCategory: 'VEHICULAR',
        confidence: 'HIGH'
      },
      scopeValidation: {
        isEmailInScope: false,
        assessmentStatus: 'OUT OF SCOPE',
        scopeReason: 'No SMTP, IMAP, POP3, SMTPS, IMAPS, or POP3S traffic identified.',
        securityPosture: 'OUT OF SCOPE',
        riskScore: 'N/A',
        routingDecision: {
          targetEngine: 'V2X Security Gateway',
          routedTrafficType: 'Vehicular Traffic (ITS-G5 / V2X)',
          isScopeAccepted: false,
          explanation: '5,313 ITS-G5 GeoNetworking/CAM/DENM frames identified. Diverted to V2X Security Gateway for IEEE 1609 / ETSI TS 102 941 PKI verification.'
        }
      },
      confidenceScores: {
        protocolConfidence: 'HIGH',
        evidenceConfidence: 'COMPLETE',
        assessmentConfidence: 'HIGH'
      },
      analystTransparency: {
        totalPackets: 5313,
        emailPackets: 0,
        smtpSessions: 0,
        imapSessions: 0,
        pop3Sessions: 0,
        detectedProtocolsSummary: 'ITS-G5 (5,313)',
        scopeStatus: 'OUT OF SCOPE',
        whyConclusionReached: [
          '5,313 packets analyzed passively.',
          'SMTP sessions: 0, IMAP sessions: 0, POP3 sessions: 0.',
          'Detected protocol: ITS-G5 (ETSI GeoNetworking / BTP CAM / DENM).',
          'Scope Validation Layer halted cryptographic email assessment per forensic mandate.',
          'Result: Assessment Out of Scope (Security Posture: NOT ASSESSABLE). Confidence: High.'
        ],
        chainOfCustodyHash: '4f89d31a57b28c3014de99824c96571a8e24bf98a723812d6a59cb4a148f95c2',
        confidenceScore: 'HIGH'
      }
    },
    sessions: [],
    findings: [],
    evidenceList: [],
    rules: DETERMINISTIC_RULES,
    assessmentStatus: 'OUT OF SCOPE',
    scopeValidation: {
      isEmailInScope: false,
      assessmentStatus: 'OUT OF SCOPE',
      scopeReason: 'No SMTP, IMAP, POP3, SMTPS, IMAPS, or POP3S traffic identified.',
      securityPosture: 'OUT OF SCOPE',
      riskScore: 'N/A',
      routingDecision: {
        targetEngine: 'V2X Security Gateway',
        routedTrafficType: 'Vehicular Traffic (ITS-G5 / V2X)',
        isScopeAccepted: false,
        explanation: '5,313 ITS-G5 frames identified. Diverted to V2X Security Gateway.'
      }
    },
    confidenceScores: {
      protocolConfidence: 'HIGH',
      evidenceConfidence: 'COMPLETE',
      assessmentConfidence: 'HIGH'
    },
    analystTransparency: {
      totalPackets: 5313,
      emailPackets: 0,
      smtpSessions: 0,
      imapSessions: 0,
      pop3Sessions: 0,
      detectedProtocolsSummary: 'ITS-G5 (5,313)',
      scopeStatus: 'OUT OF SCOPE',
      whyConclusionReached: [
        '5,313 packets analyzed passively.',
        'SMTP sessions: 0, IMAP sessions: 0, POP3 sessions: 0.',
        'Detected protocol: ITS-G5 (ETSI GeoNetworking / BTP CAM / DENM).',
        'Scope Validation Layer halted cryptographic email assessment per forensic mandate.',
        'Result: Assessment Out of Scope (Security Posture: NOT ASSESSABLE). Confidence: High.'
      ],
      chainOfCustodyHash: '4f89d31a57b28c3014de99824c96571a8e24bf98a723812d6a59cb4a148f95c2',
      confidenceScore: 'HIGH'
    }
  },
  // SCENARIO 7: Out-of-Scope Web Traffic (HTTP / HTTPS)
  {
    id: 'scenario-web-traffic',
    title: 'Scenario 7: Out-of-Scope Web Application Traffic (HTTPS/HTTP)',
    subtitle: '4,210 Packets · HTTPS/HTTP Port 443/80 · 0 Email Streams · Assessment Out of Scope',
    description: 'Enterprise web browsing capture consisting exclusively of HTTP and HTTPS web flows. Diverted to Web Application Security Gateway per Protocol-Aware Assessment Routing.',
    defaultSelectedSessionId: '',
    pcapMetadata: {
      id: 'PCAP-2026-WEB-01',
      filename: 'enterprise_gateway_https_web.pcapng',
      sha256: '7b1029c48ea92d8314e0821bf3a5682910c2834bfa902187349120194821a8bc',
      fileSizeBytes: 1984200,
      captureTimestamp: '2026-09-25 14:10:00 UTC',
      analysisTimestamp: '2026-09-25 14:10:30 UTC',
      packetCount: 4210,
      streamCount: 0,
      status: 'VERIFIED',
      confidence: 'COMPLETE',
      capturedInterface: 'eth0 (Corporate Proxy Tap)',
      notes: 'Web traffic capture. Zero email submission or mailbox access protocols.',
      captureDurationSec: 32.0,
      totalTcpFlows: 0,
      tlsHandshakeCount: 0,
      protocolClassification: {
        detectedProtocols: [
          { protocol: 'HTTPS', packetCount: 3650, percentage: 86.7, category: 'WEB' },
          { protocol: 'HTTP', packetCount: 560, percentage: 13.3, category: 'WEB' }
        ],
        counts: {
          smtp: 0,
          smtps: 0,
          imap: 0,
          imaps: 0,
          pop3: 0,
          pop3s: 0,
          http: 560,
          https: 3650,
          dns: 0,
          ssh: 0,
          ftp: 0,
          icmp: 0,
          itsG5: 0,
          v2x: 0,
          unknown: 0
        },
        totalEmailPackets: 0,
        totalNonEmailPackets: 4210,
        primaryProtocol: 'HTTPS',
        primaryCategory: 'WEB',
        confidence: 'HIGH'
      },
      scopeValidation: {
        isEmailInScope: false,
        assessmentStatus: 'OUT OF SCOPE',
        scopeReason: 'No SMTP, IMAP, POP3, SMTPS, IMAPS, or POP3S traffic identified.',
        securityPosture: 'OUT OF SCOPE',
        riskScore: 'N/A',
        routingDecision: {
          targetEngine: 'Web Security Engine',
          routedTrafficType: 'Web Traffic',
          isScopeAccepted: false,
          explanation: 'HTTP/HTTPS web traffic identified. Diverted to Web Application Security Gateway.'
        }
      },
      confidenceScores: {
        protocolConfidence: 'HIGH',
        evidenceConfidence: 'COMPLETE',
        assessmentConfidence: 'HIGH'
      },
      analystTransparency: {
        totalPackets: 4210,
        emailPackets: 0,
        smtpSessions: 0,
        imapSessions: 0,
        pop3Sessions: 0,
        detectedProtocolsSummary: 'HTTPS (3,650), HTTP (560)',
        scopeStatus: 'OUT OF SCOPE',
        whyConclusionReached: [
          '4,210 packets analyzed passively.',
          'SMTP sessions: 0, IMAP sessions: 0, POP3 sessions: 0.',
          'Detected protocol: HTTPS and HTTP web traffic.',
          'Scope Validation Layer halted cryptographic email assessment.',
          'Result: Assessment Out of Scope. Confidence: High.'
        ],
        chainOfCustodyHash: '7b1029c48ea92d8314e0821bf3a5682910c2834bfa902187349120194821a8bc',
        confidenceScore: 'HIGH'
      }
    },
    sessions: [],
    findings: [],
    evidenceList: [],
    rules: DETERMINISTIC_RULES,
    assessmentStatus: 'OUT OF SCOPE',
    scopeValidation: {
      isEmailInScope: false,
      assessmentStatus: 'OUT OF SCOPE',
      scopeReason: 'No SMTP, IMAP, POP3, SMTPS, IMAPS, or POP3S traffic identified.',
      securityPosture: 'OUT OF SCOPE',
      riskScore: 'N/A',
      routingDecision: {
        targetEngine: 'Web Security Engine',
        routedTrafficType: 'Web Traffic',
        isScopeAccepted: false,
        explanation: 'HTTP/HTTPS web traffic identified. Diverted to Web Application Security Gateway.'
      }
    },
    confidenceScores: {
      protocolConfidence: 'HIGH',
      evidenceConfidence: 'COMPLETE',
      assessmentConfidence: 'HIGH'
    },
    analystTransparency: {
      totalPackets: 4210,
      emailPackets: 0,
      smtpSessions: 0,
      imapSessions: 0,
      pop3Sessions: 0,
      detectedProtocolsSummary: 'HTTPS (3,650), HTTP (560)',
      scopeStatus: 'OUT OF SCOPE',
      whyConclusionReached: [
        '4,210 packets analyzed passively.',
        'SMTP sessions: 0, IMAP sessions: 0, POP3 sessions: 0.',
        'Detected protocol: HTTPS and HTTP web traffic.',
        'Scope Validation Layer halted cryptographic email assessment.',
        'Result: Assessment Out of Scope. Confidence: High.'
      ],
      chainOfCustodyHash: '7b1029c48ea92d8314e0821bf3a5682910c2834bfa902187349120194821a8bc',
      confidenceScore: 'HIGH'
    }
  }
];

export const DEMO_SCENARIOS: DemoScenario[] = [
  RAW_SCENARIOS[0], // Scenario 1: Modern Secure SMTP Transport (TLS 1.3)
  RAW_SCENARIOS[1], // Scenario 2: Deprecated TLS 1.0 on Exchange MTA
  RAW_SCENARIOS[2], // Scenario 3: Expired Certificate & Weak Hash on IMAP
  RAW_SCENARIOS[3], // Scenario 4: Plaintext POP3 Credentials Exposure
  RAW_SCENARIOS[4], // Scenario 5: Truncated Incomplete SMTP Capture
  RAW_SCENARIOS[5], // Scenario 6: Out-of-Scope Vehicular Telemetry (ITS-G5 / V2X)
  RAW_SCENARIOS[6]  // Scenario 7: Out-of-Scope Web Application Traffic (HTTP/HTTPS)
];

export const INITIAL_PIPELINE_STAGES: PipelineStage[] = [
  {
    id: 'pcap_ingestion',
    name: 'PCAP Ingestion & Integrity',
    status: 'completed',
    count: 1420,
    processingTimeMs: 14,
    details: 'Valid pcapng header, SHA-256 integrity hash calculated and verified against frame bounds.',
    subSteps: ['Magic bytes 0x0A0D0D0A validated', 'Interface Description Block parsed', 'Packet timestamp indexing complete']
  },
  {
    id: 'tcp_reconstruction',
    name: 'TCP Stream Reconstruction',
    status: 'completed',
    count: 18,
    processingTimeMs: 38,
    details: 'Bidirectional TCP reassembly via sliding sequence window, zero segment loss detected.',
    subSteps: ['3-way handshake alignment', 'Out-of-order segment reordering', 'Duplicate segment de-duplication']
  },
  {
    id: 'protocol_identification',
    name: 'Protocol Dissection',
    status: 'completed',
    count: 18,
    processingTimeMs: 22,
    details: 'Heuristic & port-based identification: 14 SMTP, 2 IMAP, 2 POP3 streams identified.',
    subSteps: ['RFC 5321 SMTP grammar parsing', 'RFC 3501 IMAP grammar parsing', 'RFC 1939 POP3 grammar parsing']
  },
  {
    id: 'session_extraction',
    name: 'Email Session Extraction',
    status: 'completed',
    count: 18,
    processingTimeMs: 29,
    details: 'Reconstructed client/server dialogue, banners, EHLO/HELO parameters, and session durations.',
    subSteps: ['Banner extraction', 'Client greeting correlation', 'Transaction lifecycle bounds established']
  },
  {
    id: 'starttls_detection',
    name: 'STARTTLS Negotiation Detection',
    status: 'completed',
    count: 15,
    processingTimeMs: 18,
    details: 'STARTTLS advertisement and client request state tracking. Cleartext-to-TLS phase shift identified.',
    subSteps: ['Capability advertisement verified', 'Client STARTTLS command detected', 'Server 220 confirmation tracked']
  },
  {
    id: 'tls_handshake_analysis',
    name: 'TLS Handshake Dissection',
    status: 'completed',
    count: 16,
    processingTimeMs: 45,
    details: 'Extracted TLS record layers, versions, cipher suites, key exchange methods, and PFS flags.',
    subSteps: ['Client Hello cipher offerings', 'Server Hello selected parameters', 'Key exchange mechanics validated']
  },
  {
    id: 'x509_analysis',
    name: 'X.509 Certificate Chain Analysis',
    status: 'completed',
    count: 14,
    processingTimeMs: 52,
    details: 'ASN.1 DER parsing of presented certificates: validity, key size, signature algorithm, SANs.',
    subSteps: ['Validity period verification', 'Key size & algorithm audit', 'Signature algorithm hash strength check']
  },
  {
    id: 'crypto_evidence_generation',
    name: 'Cryptographic Evidence Correlation',
    status: 'completed',
    count: 24,
    processingTimeMs: 31,
    details: 'Packet offsets, frame numbers, and raw bytes bound to forensic evidence items.',
    subSteps: ['Frame number indexing', 'Hex sample generation', 'Confidence scoring calculation']
  },
  {
    id: 'deterministic_security_rules',
    name: 'Deterministic Security Rules',
    status: 'completed',
    count: 8,
    processingTimeMs: 12,
    details: 'Evaluated against RFC 8996, RFC 9325, RFC 8314, NIST SP 800-52r2, and CAB Forum baseline standards.',
    subSteps: ['Rule evaluation matrix execution', 'Definitive fact generation', 'Severity classification']
  },
  {
    id: 'ai_contextual_analysis',
    name: 'AI/ML Contextual Reasoning',
    status: 'completed',
    count: 3,
    processingTimeMs: 280,
    details: 'Contextual risk synthesis, interaction impact analysis, and remediation priority ranking.',
    subSteps: ['Structured evidence serialization', 'Context correlation engine', 'Triage priority generation']
  },
  {
    id: 'risk_and_posture_engine',
    name: 'Risk & Posture Aggregation',
    status: 'completed',
    count: 1,
    processingTimeMs: 8,
    details: 'Overall cryptographic security posture classified as AT RISK based on deterministic findings.',
    subSteps: ['Contributing factor scoring', 'Category breakdown synthesis', 'Posture state determination']
  },
  {
    id: 'prioritized_findings',
    name: 'Evidence-Linked Findings',
    status: 'completed',
    count: 3,
    processingTimeMs: 10,
    details: '3 findings generated with direct cryptographic evidence traceability and action plans.',
    subSteps: ['Evidence linkage verification', 'Audit action recommendation generation']
  }
];
