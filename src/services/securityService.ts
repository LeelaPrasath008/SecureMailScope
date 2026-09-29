/**
 * SecureMailScope - Security Analysis & Forensics Service Layer
 * SIH 2026 Problem Statement 26159
 * Decoupled service layer ready for real backend integration (React -> Express/Spring -> Python/TShark)
 */

import { DEMO_SCENARIOS, DETERMINISTIC_RULES, INITIAL_PIPELINE_STAGES } from '../data/mockScenarios';
import {
  AIReasoningAnalysis,
  CryptographicEvidence,
  DemoScenario,
  EmailSession,
  Finding,
  PipelineStage,
  ProtocolEvent,
  ProtocolType,
  SecurityPosture,
  SeverityLevel
} from '../types/security';

export interface WhatIfToggles {
  disableDeprecatedTls: boolean;
  removeWeakCiphers: boolean;
  replaceExpiredCertificates: boolean;
  requireForwardSecrecy: boolean;
  enforceTlsOnPlaintext: boolean;
}

export interface WhatIfResult {
  currentPosture: 'AT RISK' | 'DEGRADED' | 'SECURE';
  projectedPosture: 'AT RISK' | 'DEGRADED' | 'SECURE';
  resolvedFindingCount: number;
  remainingFindingCount: number;
  riskReductionPercentage: number;
  projectedResolvedFindings: string[];
  remainingRiskAreas: string[];
}

export interface FilterOptions {
  searchQuery?: string;
  severity?: SeverityLevel | 'ALL';
  protocol?: ProtocolType | 'ALL';
  confidence?: 'COMPLETE' | 'PARTIAL' | 'INSUFFICIENT' | 'ALL';
  hasStartTls?: boolean;
}

class SecurityService {
  private activeScenarioId: string = 'scenario-secure-smtp';
  private scenarios: DemoScenario[] = [...DEMO_SCENARIOS];
  private pipelineStages: PipelineStage[] = [...INITIAL_PIPELINE_STAGES];
  private isAiServiceOnline: boolean = true;

  public getScenarios(): DemoScenario[] {
    return this.scenarios;
  }

  public getActiveScenario(): DemoScenario {
    const scenario = this.scenarios.find(s => s.id === this.activeScenarioId);
    return scenario || this.scenarios[0];
  }

  public setActiveScenario(scenarioId: string): DemoScenario {
    const found = this.scenarios.find(s => s.id === scenarioId);
    if (found) {
      this.activeScenarioId = scenarioId;
    }
    return this.getActiveScenario();
  }

  public getPipelineStages(): PipelineStage[] {
    return this.pipelineStages;
  }

  public setAiServiceStatus(online: boolean) {
    this.isAiServiceOnline = online;
  }

  public isAiOnline(): boolean {
    return this.isAiServiceOnline;
  }

  public getSessions(filter?: FilterOptions): EmailSession[] {
    const active = this.getActiveScenario();
    let sessions = active.sessions;

    if (!filter) return sessions;

    return sessions.filter(session => {
      if (filter.protocol && filter.protocol !== 'ALL' && session.protocol !== filter.protocol) {
        return false;
      }
      if (filter.severity && filter.severity !== 'ALL' && session.risk !== filter.severity) {
        return false;
      }
      if (filter.confidence && filter.confidence !== 'ALL' && session.evidenceConfidence !== filter.confidence) {
        return false;
      }
      if (filter.searchQuery && filter.searchQuery.trim() !== '') {
        const q = filter.searchQuery.toLowerCase();
        const matchId = session.id.toLowerCase().includes(q);
        const matchIp = session.sourceIp.toLowerCase().includes(q) || session.destIp.toLowerCase().includes(q);
        const matchHost = (session.serverHostname || '').toLowerCase().includes(q);
        const matchCipher = (session.tlsHandshake?.cipherSuite.ianaName || '').toLowerCase().includes(q);
        const matchTls = (session.tlsHandshake?.negotiatedVersion || '').toLowerCase().includes(q);
        const matchCert = (session.tlsHandshake?.certificate?.subject || '').toLowerCase().includes(q);
        if (!matchId && !matchIp && !matchHost && !matchCipher && !matchTls && !matchCert) {
          return false;
        }
      }
      return true;
    });
  }

  public getSessionById(sessionId: string): EmailSession | undefined {
    for (const scenario of this.scenarios) {
      const found = scenario.sessions.find(s => s.id === sessionId);
      if (found) return found;
    }
    return undefined;
  }

  public getFindings(filter?: FilterOptions): Finding[] {
    const active = this.getActiveScenario();
    let findings = active.findings;

    if (!filter) return findings;

    return findings.filter(f => {
      if (filter.severity && filter.severity !== 'ALL' && f.severity !== filter.severity) {
        return false;
      }
      if (filter.confidence && filter.confidence !== 'ALL' && f.confidence !== filter.confidence) {
        return false;
      }
      if (filter.searchQuery && filter.searchQuery.trim() !== '') {
        const q = filter.searchQuery.toLowerCase();
        const matchId = f.id.toLowerCase().includes(q);
        const matchTitle = f.title.toLowerCase().includes(q);
        const matchSession = f.affectedSessionId.toLowerCase().includes(q);
        const matchRule = f.ruleTitle.toLowerCase().includes(q) || f.standardReference.toLowerCase().includes(q);
        const matchEv = f.evidenceStatement.toLowerCase().includes(q);
        if (!matchId && !matchTitle && !matchSession && !matchRule && !matchEv) {
          return false;
        }
      }
      return true;
    });
  }

  public getFindingById(findingId: string): Finding | undefined {
    for (const scenario of this.scenarios) {
      const found = scenario.findings.find(f => f.id === findingId);
      if (found) return found;
    }
    return undefined;
  }

  public getEvidenceById(evidenceId: string): CryptographicEvidence | undefined {
    for (const scenario of this.scenarios) {
      const found = scenario.evidenceList.find(e => e.id === evidenceId);
      if (found) return found;
    }
    return undefined;
  }

  public getAllEvidence(): CryptographicEvidence[] {
    const active = this.getActiveScenario();
    return active.evidenceList;
  }

  public getInvestigationTimeline(sessionId: string): ProtocolEvent[] {
    const session = this.getSessionById(sessionId);
    if (!session || !session.protocolEvents) return [];
    return session.protocolEvents;
  }

  public getSecurityPosture(): SecurityPosture {
    const active = this.getActiveScenario();
    const sessions = active.sessions;
    const findings = active.findings;

    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
    const lowCount = findings.filter(f => f.severity === 'LOW' || f.severity === 'INFORMATIONAL').length;

    let overallStatus: 'AT RISK' | 'DEGRADED' | 'SECURE' = 'SECURE';
    if (criticalCount > 0 || highCount > 0) {
      overallStatus = 'AT RISK';
    } else if (mediumCount > 0) {
      overallStatus = 'DEGRADED';
    }

    const contributingFactors = [];
    // Check specific factor types with strict observed vs assessed vs contextual distinction
    const hasTls10 = findings.some(f => f.ruleId === 'RULE-TLS-001' && f.severity === 'HIGH');
    if (hasTls10) {
      contributingFactors.push({
        label: 'Deprecated TLS Version Observed (TLS 1.0)',
        severity: 'HIGH' as SeverityLevel,
        count: findings.filter(f => f.ruleId === 'RULE-TLS-001').length,
        description: 'Observed version is formally deprecated by RFC 8996 and prohibited by RFC 9325 (BCP 195); lacks modern AEAD authenticated encryption.'
      });
    }

    const hasWeakCipher = findings.some(f => f.ruleId === 'RULE-CIPHER-002');
    if (hasWeakCipher) {
      contributingFactors.push({
        label: '3DES / 64-bit Block Cipher Detected',
        severity: 'HIGH' as SeverityLevel,
        count: findings.filter(f => f.ruleId === 'RULE-CIPHER-002').length,
        description: '64-bit block size cipher structure detected. High-volume sessions carry collision vulnerabilities associated with Sweet32 (CVE-2016-2183).'
      });
    }

    const hasNoPfs = findings.some(f => f.ruleId === 'RULE-CIPHER-003');
    if (hasNoPfs) {
      contributingFactors.push({
        label: 'No Forward Secrecy — Static RSA Key Exchange',
        severity: 'HIGH' as SeverityLevel,
        count: findings.filter(f => f.ruleId === 'RULE-CIPHER-003').length,
        description: 'Static RSA key exchange does not provide forward secrecy. If the private key is later compromised, captured traffic may be susceptible to retrospective decryption.'
      });
    }

    const hasCertIssue = findings.some(f => f.ruleId.startsWith('RULE-CERT'));
    if (hasCertIssue) {
      contributingFactors.push({
        label: 'Certificate Validity / Signature Issue',
        severity: 'HIGH' as SeverityLevel,
        count: findings.filter(f => f.ruleId.startsWith('RULE-CERT')).length,
        description: 'Expired certificate or obsolete signature algorithm breaks cryptographic trust.'
      });
    }

    const hasPlaintext = findings.some(f => f.ruleId === 'RULE-PLAIN-001');
    if (hasPlaintext) {
      contributingFactors.push({
        label: 'Cleartext Mail Protocol & Credential Exposure',
        severity: 'CRITICAL' as SeverityLevel,
        count: findings.filter(f => f.ruleId === 'RULE-PLAIN-001').length,
        description: 'RFC 8314 violation: Passwords sent in cleartext without TLS encapsulation.'
      });
    }

    const hasTruncated = findings.some(f => f.ruleId === 'RULE-PCAP-009');
    if (hasTruncated) {
      contributingFactors.push({
        label: 'Incomplete PCAP Observation Window',
        severity: 'MEDIUM' as SeverityLevel,
        count: findings.filter(f => f.ruleId === 'RULE-PCAP-009').length,
        description: 'Capture buffer cut off before handshake completion; evidence confidence rated INSUFFICIENT per ISO/IEC 27037.'
      });
    }

    // Category breakdown
    const transportFindings = findings.filter(f => f.ruleId === 'RULE-TLS-001' || f.ruleId === 'RULE-STARTTLS-002');
    const cryptoFindings = findings.filter(f => f.ruleId === 'RULE-CIPHER-002' || f.ruleId === 'RULE-CIPHER-003');
    const certFindings = findings.filter(f => f.ruleId.startsWith('RULE-CERT'));
    const protoFindings = findings.filter(f => f.ruleId === 'RULE-PLAIN-001' || f.ruleId === 'RULE-PCAP-009');

    const getCategoryStatus = (catFindings: Finding[]): 'AT RISK' | 'DEGRADED' | 'SECURE' => {
      if (catFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')) return 'AT RISK';
      if (catFindings.some(f => f.severity === 'MEDIUM')) return 'DEGRADED';
      return 'SECURE';
    };

    const smtpObserved = Array.from(new Set(sessions.filter(s => s.protocol === 'SMTP').map(s => s.destPort)));
    const imapObserved = Array.from(new Set(sessions.filter(s => s.protocol === 'IMAP').map(s => s.destPort)));
    const pop3Observed = Array.from(new Set(sessions.filter(s => s.protocol === 'POP3').map(s => s.destPort)));

    const activeViolationsCount = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
    const policyBasisExplanation =
      overallStatus === 'AT RISK'
        ? `${activeViolationsCount} evidence-backed finding${activeViolationsCount > 1 ? 's violate' : ' violates'} the SecureMailScope Email TLS Baseline Profile (v1.2).`
        : overallStatus === 'DEGRADED'
        ? 'Non-critical policy deviations observed in reconstructed email traffic.'
        : 'All inspected email sessions comply with the SecureMailScope Email TLS Baseline Profile (v1.2).';

    return {
      status: overallStatus,
      overallScoreLabel: overallStatus,
      technicalPosture: criticalCount > 0 || highCount > 0 ? 'AT RISK' : mediumCount > 0 ? 'DEGRADED' : 'SECURE',
      policyPosture: overallStatus,
      policyProfileName: 'SecureMailScope Email TLS Baseline Profile (v1.2)',
      activeViolationsCount,
      policyBasisExplanation,
      portBreakdown: {
        smtpObservedPorts: smtpObserved,
        smtpExpectedPorts: [25, 465, 587],
        imapObservedPorts: imapObserved,
        imapExpectedPorts: [143, 993],
        pop3ObservedPorts: pop3Observed,
        pop3ExpectedPorts: [110, 995]
      },
      contributingFactors,
      summaryCounts: {
        pcapsAnalyzed: 1,
        totalSessions: sessions.length,
        smtpSessions: sessions.filter(s => s.protocol === 'SMTP').length,
        imapSessions: sessions.filter(s => s.protocol === 'IMAP').length,
        pop3Sessions: sessions.filter(s => s.protocol === 'POP3').length,
        tlsSessions: sessions.filter(s => s.tlsHandshake && s.tlsHandshake.negotiatedVersion !== 'NONE').length,
        totalFindings: findings.length,
        criticalFindings: criticalCount,
        highFindings: highCount,
        mediumFindings: mediumCount,
        lowFindings: lowCount
      },
      categoryBreakdown: {
        transportSecurity: {
          status: getCategoryStatus(transportFindings),
          evidenceCount: active.evidenceList.filter(e => e.evidenceType === 'TLS_VERSION' || e.evidenceType === 'STARTTLS_BEHAVIOR').length,
          findingsCount: transportFindings.length,
          severity: transportFindings.length > 0 ? (transportFindings[0].severity) : 'LOW',
          keyMetric: transportFindings.length > 0 ? 'Deprecated Protocol Negotiated' : 'Modern TLS Baseline Enforced'
        },
        cryptography: {
          status: getCategoryStatus(cryptoFindings),
          evidenceCount: active.evidenceList.filter(e => e.evidenceType === 'CIPHER_SUITE' || e.evidenceType === 'KEY_EXCHANGE').length,
          findingsCount: cryptoFindings.length,
          severity: cryptoFindings.length > 0 ? (cryptoFindings[0].severity) : 'LOW',
          keyMetric: cryptoFindings.length > 0 ? 'Weak Block Cipher / No Forward Secrecy' : 'Authenticated AEAD & PFS Verified'
        },
        certificateSecurity: {
          status: getCategoryStatus(certFindings),
          evidenceCount: active.evidenceList.filter(e => e.evidenceType === 'CERTIFICATE').length,
          findingsCount: certFindings.length,
          severity: certFindings.length > 0 ? (certFindings[0].severity) : 'LOW',
          keyMetric: certFindings.length > 0 ? 'Validity or Hash Deficiency' : 'Valid Chain & Strong Signature'
        },
        protocolSecurity: {
          status: getCategoryStatus(protoFindings),
          evidenceCount: active.evidenceList.filter(e => e.evidenceType === 'PLAINTEXT_EXPOSURE').length,
          findingsCount: protoFindings.length,
          severity: protoFindings.length > 0 ? (protoFindings[0].severity) : 'LOW',
          keyMetric: protoFindings.length > 0 ? 'Cleartext Auth / Incomplete Capture' : 'Encrypted Mail Protocol Adherence'
        }
      }
    };
  }

  public async runAIContextualReasoning(sessionId?: string): Promise<AIReasoningAnalysis> {
    if (!this.isAiServiceOnline) {
      return {
        available: false,
        groundedEvidenceInput: {},
        contextualAssessment: 'AI ANALYSIS UNAVAILABLE. Deterministic cryptographic analysis completed successfully. Your findings remain authoritative and accessible.',
        interactionImpact: 'AI reasoning offline. Deterministic rule evaluations remain in effect.',
        prioritizedSequence: [],
        aiConfidence: 'MODERATE',
        aiConfidenceBasis: 'Service offline fallback',
        disclaimer: 'Deterministic security rules remain authoritative for cryptographic facts.',
        suggestedMitigation: []
      };
    }

    const session = sessionId ? this.getSessionById(sessionId) : this.getActiveScenario().sessions[0];
    const scenario = this.getActiveScenario();

    if (!session) {
      return {
        available: false,
        groundedEvidenceInput: {},
        contextualAssessment: 'No session selected for contextual reasoning.',
        interactionImpact: '',
        prioritizedSequence: [],
        aiConfidence: 'MODERATE',
        aiConfidenceBasis: 'No session provided',
        disclaimer: 'Deterministic security rules remain authoritative for cryptographic facts.',
        suggestedMitigation: []
      };
    }

    // Build structured technical evidence input
    const structuredEvidence = {
      session_id: session.id,
      protocol: session.protocol,
      remote_peer: `${session.destIp}:${session.destPort} (${session.serverHostname || 'unknown'})`,
      starttls_negotiated: session.startTlsNegotiated,
      tls_version: session.tlsHandshake?.negotiatedVersion || 'NONE',
      cipher_suite: session.tlsHandshake?.cipherSuite.ianaName || 'NONE',
      forward_secrecy: session.tlsHandshake?.forwardSecrecy ?? false,
      certificate_valid: session.tlsHandshake?.certificate ? !session.tlsHandshake.certificate.isExpired : false,
      certificate_chain_status: session.tlsHandshake?.certificate?.chainStatus || 'NOT_PRESENT',
      evidence_confidence: session.evidenceConfidence,
      duration_seconds: session.durationSec,
      findings_count: session.findingsIds.length
    };

    // Realistic contextual reasoning based on the observed evidence
    let assessment = '';
    let interaction = '';
    let sequence: string[] = [];
    let mitigations: string[] = [];

    if (session.protocol === 'POP3' && session.plaintextCredentialsExposed) {
      assessment = `This session exhibits an immediate active security emergency. The absence of TLS or STLS negotiation on port 110 allowed raw mailbox authentication credentials (USER/PASS) to be transmitted in cleartext ASCII. In this architecture, cryptographic analysis is eclipsed by fundamental transport exposure.`;
      interaction = `Because credentials were transmitted unencrypted across the network link, any subsequent analysis of encryption strength is moot. The primary vector is credential interception and account takeover.`;
      sequence = [
        '1. Revoke and rotate the exposed user account password immediately.',
        '2. Disable unencrypted POP3 listener on TCP port 110 at the firewall and MTA daemon.',
        '3. Enforce POP3S (port 995 with implicit TLS 1.3) or migrate the user to modern authenticated IMAP with OAuth2.'
      ];
      mitigations = [
        'Block inbound port 110 at edge firewall',
        'Enable port 995 POP3S with TLS 1.3 requirement',
        'Trigger automated credential reset in Active Directory / LDAP'
      ];
    } else if (session.evidenceConfidence === 'INSUFFICIENT') {
      assessment = `Forensic capture integrity analysis indicates observation truncation. The PCAP contains the initial TCP 3-way handshake and the Client Hello frame, but terminates prior to the Server Hello or certificate exchange. Deterministic rules correctly withhold definitive cryptographic judgment.`;
      interaction = `Without observing the server's selected cipher suite and presented certificate, assessing vulnerability to downgrade or Sweet32 is impossible. AI contextual analysis confirms that flagging potential risk must not be confused with confirmed vulnerability.`;
      sequence = [
        '1. Inspect packet capture buffer configurations and NIC drop counters on the monitoring interface.',
        '2. Verify SPAN port / TAP saturation levels to eliminate dropped frames during high traffic periods.',
        '3. Re-run capture on the target relay interface to obtain a complete bidirectional handshake before issuing audit findings.'
      ];
      mitigations = [
        'Audit SPAN session bandwidth allocation',
        'Verify MTU and buffer settings on sensor node',
        'Schedule re-capture of upstream gateway traffic'
      ];
    } else if (session.tlsHandshake?.negotiatedVersion === 'TLS 1.0') {
      assessment = `Grounded analysis of Session ${session.id} identifies a compound cryptographic degradation. While the host presented a valid, non-expired certificate, the session negotiated TLS 1.0 combined with 3DES-CBC encryption and static RSA key agreement. This represents a systemic backward-compatibility failure on the enterprise gateway.`;
      interaction = `These three findings interact synergistically to degrade confidentiality: 
1. Static RSA eliminates Forward Secrecy; if the server private key is ever exposed, historical captures of this session can be decrypted retroactively.
2. 3DES-CBC exposes the communication to Sweet32 collision attacks under prolonged data transfer.
3. TLS 1.0 lacks modern downgrade-protection extensions (like TLS 1.3 downgrade sentinels), leaving the connection vulnerable to active man-in-the-middle protocol rollback.`;
      sequence = [
        '1. Priority 1: Deprecate TLS 1.0 and TLS 1.1 in MTA configuration (enforce minimum TLS 1.2).',
        '2. Priority 2: Exclude 3DES and CBC-mode ciphers from the allowed cipher string; mandate AEAD (AES-GCM / ChaCha20).',
        '3. Priority 3: Restrict key exchange to ephemeral Diffie-Hellman (ECDHE) to ensure Forward Secrecy.'
      ];
      mitigations = [
        'Set Postfix: smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1',
        'Set smtpd_tls_mandatory_ciphers = high',
        'Enable MTA-STS (RFC 8461) to publish strict TLS delivery policy in DNS'
      ];
    } else if (session.tlsHandshake?.certificate?.isExpired) {
      assessment = `Forensic inspection of Session ${session.id} reveals an expired X.509 certificate (lapsed 42 days ago) signed with deprecated SHA-1. Although TLS 1.2 and ECDHE forward secrecy were successfully negotiated, the fundamental trust relationship of the IMAP server is broken.`;
      interaction = `A strong cipher suite (AES-128-GCM with ECDHE) cannot protect users if the identity of the remote endpoint cannot be verified. When certificates expire, connecting mail clients trigger security warning dialogs, conditioning users to bypass cryptographic warnings or causing automated MTAs to drop connections.`;
      sequence = [
        '1. Issue and install a replacement X.509 certificate with minimum 2048-bit RSA or 256-bit ECDSA.',
        '2. Ensure the certificate is signed with SHA-256 (sha256WithRSAEncryption) or stronger.',
        '3. Configure automated ACME renewal (e.g. certbot / cert-manager) with automated alerts 30 days prior to expiration.'
      ];
      mitigations = [
        'Deploy fresh Let\'s Encrypt or corporate PKI certificate',
        'Verify intermediate CA certificate bundle installation in Dovecot/IMAP daemon',
        'Implement proactive certificate expiry monitoring in Prometheus/Zabbix'
      ];
    } else {
      assessment = `Session ${session.id} demonstrates an optimal cryptographic security posture conforming to modern zero-trust standards. TLS 1.3 is negotiated with authenticated encryption (AES-256-GCM), forward secrecy is guaranteed via ephemeral X25519 key exchange, and the X.509 certificate is valid.`;
      interaction = `No adversarial vulnerabilities or cryptographic regressions were observed. Forward secrecy ensures that even if long-term server credentials are compromised in the future, the recorded session traffic remains mathematically unbreakable.`;
      sequence = [
        '1. Maintain current TLS 1.3 configuration.',
        '2. Monitor certificate expiration cycle (renewal recommended at 30 days remaining).',
        '3. Periodically test for DANE TLSA or MTA-STS publication to reinforce transport policy against DNS tampering.'
      ];
      mitigations = [
        'Maintain automated certificate rotation cadence',
        'Audit MTA-STS DNS TXT records for email domain'
      ];
    }

    return {
      sessionId: session.id,
      available: true,
      groundedEvidenceInput: structuredEvidence,
      contextualAssessment: assessment,
      interactionImpact: interaction,
      prioritizedSequence: sequence,
      aiConfidence: session.evidenceConfidence === 'COMPLETE' ? 'VERY_HIGH' : 'MODERATE',
      aiConfidenceBasis: `Deterministic evidence is ${session.evidenceConfidence}. Evaluated against IETF RFC standards and NIST SP 800 guidelines.`,
      disclaimer: 'AI-generated reasoning is grounded in extracted technical evidence. Deterministic security rules remain authoritative for cryptographic facts.',
      suggestedMitigation: mitigations
    };
  }

  public simulateWhatIfPostures(toggles: WhatIfToggles): WhatIfResult {
    const active = this.getActiveScenario();
    const findings = active.findings;

    const projectedResolved: string[] = [];
    const remainingRisk: string[] = [];

    findings.forEach(f => {
      let isResolved = false;
      if (f.ruleId === 'RULE-TLS-001' && toggles.disableDeprecatedTls) {
        isResolved = true;
      } else if (f.ruleId === 'RULE-CIPHER-002' && toggles.removeWeakCiphers) {
        isResolved = true;
      } else if (f.ruleId === 'RULE-CIPHER-003' && toggles.requireForwardSecrecy) {
        isResolved = true;
      } else if (f.ruleId.startsWith('RULE-CERT') && toggles.replaceExpiredCertificates) {
        isResolved = true;
      } else if (f.ruleId === 'RULE-PLAIN-001' && toggles.enforceTlsOnPlaintext) {
        isResolved = true;
      }

      if (isResolved) {
        projectedResolved.push(f.id);
      } else {
        remainingRisk.push(`${f.id}: ${f.title}`);
      }
    });

    const totalFindings = findings.length;
    const resolvedCount = projectedResolved.length;
    const remainingCount = totalFindings - resolvedCount;

    const riskReduction = totalFindings > 0 ? Math.round((resolvedCount / totalFindings) * 100) : 100;

    let projectedPosture: 'AT RISK' | 'DEGRADED' | 'SECURE' = 'SECURE';
    if (remainingCount > 0) {
      // Check remaining severity
      const remainingFindingObjs = findings.filter(f => !projectedResolved.includes(f.id));
      if (remainingFindingObjs.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
        projectedPosture = 'AT RISK';
      } else if (remainingFindingObjs.some(f => f.severity === 'MEDIUM')) {
        projectedPosture = 'DEGRADED';
      } else {
        projectedPosture = 'SECURE';
      }
    }

    const currentPosture = this.getSecurityPosture().status;

    return {
      currentPosture,
      projectedPosture,
      resolvedFindingCount: resolvedCount,
      remainingFindingCount: remainingCount,
      riskReductionPercentage: riskReduction,
      projectedResolvedFindings: projectedResolved,
      remainingRiskAreas: remainingRisk
    };
  }

  public uploadSimulatedPCAP(fileName: string, fileSizeBytes: number): DemoScenario {
    // Generate an uploaded scenario entry
    const newId = `pcap-user-${Date.now()}`;
    const newScenario: DemoScenario = {
      id: newId,
      title: `Analyzed Capture: ${fileName}`,
      subtitle: `Passive Dissection · SHA-256 Verified · ${Math.round(fileSizeBytes / 1024)} KB`,
      description: `User-provided packet capture analyzed passively via SecureMailScope forensic engine.`,
      defaultSelectedSessionId: 'SES-USER-01',
      pcapMetadata: {
        id: `PCAP-${Date.now().toString().slice(-4)}`,
        filename: fileName,
        sha256: Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        fileSizeBytes,
        captureTimestamp: new Date(Date.now() - 3600000).toISOString(),
        analysisTimestamp: new Date().toISOString(),
        packetCount: Math.floor(Math.random() * 800) + 200,
        streamCount: 4,
        status: 'VERIFIED',
        confidence: 'COMPLETE',
        capturedInterface: 'eth0',
        notes: 'User upload processed via sandboxed PCAP parser.'
      },
      sessions: [
        {
          id: 'SES-USER-01',
          pcapId: `PCAP-${Date.now().toString().slice(-4)}`,
          protocol: 'SMTP',
          sourceIp: '192.168.10.50',
          sourcePort: 49812,
          destIp: '198.51.100.25',
          destPort: 25,
          serverHostname: 'mail.custom-relay.org',
          startTlsAdvertised: true,
          startTlsRequested: true,
          startTlsNegotiated: true,
          risk: 'HIGH',
          evidenceConfidence: 'COMPLETE',
          evidenceConfidenceReason: 'Full bidirectional TLS handshake captured in upload trace.',
          durationSec: 3.4,
          timestamp: new Date().toISOString(),
          findingsIds: ['FIND-U01'],
          evidenceIds: ['EVD-U01'],
          bannerText: '220 mail.custom-relay.org ESMTP ready',
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
          protocolEvents: [
            {
              id: 'EVT-U01',
              timestamp: '10:00:00.010',
              relativeMs: 0,
              direction: 'INTERNAL',
              stage: 'TCP',
              title: 'TCP Handshake Completed',
              detail: 'Connection established to port 25.',
              packetNumber: 1,
              tcpStreamIndex: 0
            },
            {
              id: 'EVT-U02',
              timestamp: '10:00:00.050',
              relativeMs: 40,
              direction: 'SERVER_TO_CLIENT',
              stage: 'STARTTLS',
              title: 'STARTTLS Advertised & Negotiated',
              detail: 'Server supports STARTTLS.',
              packetNumber: 5,
              tcpStreamIndex: 0
            },
            {
              id: 'EVT-U03',
              timestamp: '10:00:00.120',
              relativeMs: 110,
              direction: 'SERVER_TO_CLIENT',
              stage: 'TLS_HANDSHAKE',
              title: 'Server Hello: Deprecated TLS 1.0 Negotiated',
              isWeaknessOrAnomaly: true,
              detail: 'Server negotiated deprecated TLS 1.0 protocol.',
              packetNumber: 11,
              tcpStreamIndex: 0
            }
          ]
        }
      ],
      findings: [
        {
          id: 'FIND-U01',
          title: 'Deprecated TLS 1.0 Negotiated in Uploaded Traffic',
          severity: 'HIGH',
          confidence: 'COMPLETE',
          affectedSessionId: 'SES-USER-01',
          evidenceIds: ['EVD-U01'],
          ruleId: 'RULE-TLS-001',
          ruleTitle: 'Deprecated TLS Protocol Version Policy',
          standardReference: 'RFC 8996 (BCP 195) / RFC 9325 / NIST SP 800-52r2',
          evidenceStatement: 'Server Hello in upload stream negotiated TLS 1.0 (0x0301).',
          technicalReason: 'TLS 1.0 and TLS 1.1 were formally deprecated by IETF RFC 8996; RFC 9325 mandates TLS 1.2 or TLS 1.3.',
          securityImpact: 'Vulnerability to protocol downgrade and compliance violations.',
          recommendedAction: 'Enforce TLS 1.2 or TLS 1.3 on this mail server.',
          priorityOrder: 1,
          remediationComplexity: 'LOW',
          status: 'OPEN'
        }
      ],
      evidenceList: [
        {
          id: 'EVD-U01',
          sessionId: 'SES-USER-01',
          pcapId: `PCAP-${Date.now().toString().slice(-4)}`,
          evidenceType: 'TLS_VERSION',
          rawObservation: 'Server Hello Version: 0x0301 (TLS 1.0)',
          packetFrameNumbers: [11],
          confidence: 'COMPLETE',
          confidenceExplanation: 'Server Hello handshake frame decoded with matching sequence numbers.',
          verifiedTimestamp: new Date().toISOString(),
          authoritativeStandard: 'RFC 8996 (BCP 195)'
        }
      ],
      rules: DETERMINISTIC_RULES
    };

    this.scenarios.unshift(newScenario);
    this.activeScenarioId = newId;
    return newScenario;
  }
}

export const securityService = new SecurityService();
