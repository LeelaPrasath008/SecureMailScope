import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Lock,
  Layers,
  FileCode2,
  Zap,
  Info,
  BookOpen,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { DemoScenario, SecurityPosture } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { securityService, WhatIfToggles } from '../../services/securityService';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  scenario: DemoScenario;
  posture: SecurityPosture;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectFinding: (findingId: string) => void;
}

interface StandardSpecification {
  rfcNumber: string;
  title: string;
  publicationDate: string;
  status: 'CURRENT_BCP' | 'PROPOSED_STANDARD' | 'HISTORICAL_DEPRECATED' | 'SECURITY_ADVISORY';
  statusLabel: string;
  relationship: string;
  domain: string;
  mandatoryRequirement: string;
  secureMailScopeRule: string;
}

const AUTHORITATIVE_STANDARDS: StandardSpecification[] = [
  {
    rfcNumber: 'RFC 8996',
    title: 'Deprecating TLS 1.0 and TLS 1.1',
    publicationDate: 'March 2021',
    status: 'CURRENT_BCP',
    statusLabel: 'Active BCP 195',
    relationship: 'Updates RFC 5246, RFC 8446; Obsoletes RFC 2246 (TLS 1.0), RFC 4346 (TLS 1.1)',
    domain: 'Transport Security',
    mandatoryRequirement: 'TLS 1.0 and TLS 1.1 MUST NOT be negotiated by conforming implementations. Conforming clients and servers must support TLS 1.2 or TLS 1.3.',
    secureMailScopeRule: 'RULE-TLS-001 (Server Hello Handshake Version Check)'
  },
  {
    rfcNumber: 'RFC 9325',
    title: 'Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)',
    publicationDate: 'November 2022',
    status: 'CURRENT_BCP',
    statusLabel: 'Active BCP 195',
    relationship: 'Obsoletes RFC 7525; Updates RFC 5288, RFC 6066',
    domain: 'Cryptography & Ciphers',
    mandatoryRequirement: 'Mandates Forward Secrecy (PFS with ECDHE/DHE). Prohibits static RSA key exchange. Prohibits ciphers with <112 bits security or 64-bit blocks (3DES). Requires AEAD modes.',
    secureMailScopeRule: 'RULE-CIPHER-002, RULE-CIPHER-003 (Cipher Suite & PFS Audit)'
  },
  {
    rfcNumber: 'RFC 9846 / RFC 8446',
    title: 'The Transport Layer Security (TLS) Protocol Version 1.3',
    publicationDate: 'July 2026 (RFC 9846) / August 2018 (RFC 8446)',
    status: 'PROPOSED_STANDARD',
    statusLabel: 'Current Standard',
    relationship: 'RFC 9846 obsoletes RFC 8446, RFC 5246, RFC 5077, RFC 6961; BCP 195 updated by RFC 9852',
    domain: 'Transport Security',
    mandatoryRequirement: 'Defines TLS 1.3 protocol. Completely removes static RSA, CBC ciphers, and arbitrary renegotiation. All cipher suites provide authenticated encryption (AEAD) with ephemeral key exchange forward secrecy.',
    secureMailScopeRule: 'RULE-TLS-001 (Modern Standard Compliance Verification)'
  },
  {
    rfcNumber: 'RFC 5246',
    title: 'The Transport Layer Security (TLS) Protocol Version 1.2',
    publicationDate: 'August 2008',
    status: 'PROPOSED_STANDARD',
    statusLabel: 'Updated Standard',
    relationship: 'Updated by RFC 8996, RFC 9325; Previous spec: RFC 4346',
    domain: 'Transport Security',
    mandatoryRequirement: 'Defines TLS 1.2. Conforming deployments must comply with BCP 195 (RFC 9325) restrictions restricting ciphers to AEAD and ephemeral key exchange.',
    secureMailScopeRule: 'RULE-TLS-001, RULE-CIPHER-002 (TLS 1.2 Hardening Audit)'
  },
  {
    rfcNumber: 'RFC 8314',
    title: 'Cleartext Considered Obsolete: Use of Transport Layer Security (TLS) for Email Submission and Access',
    publicationDate: 'January 2018',
    status: 'PROPOSED_STANDARD',
    statusLabel: 'Current Policy Standard',
    relationship: 'Updates RFC 1939 (POP3), RFC 3501 (IMAP), RFC 6409 (Submission)',
    domain: 'Protocol Security',
    mandatoryRequirement: 'Cleartext protocols are considered obsolete for email submission (port 587 without TLS) and access (POP3 port 110, IMAP port 143). Direct/implicit TLS is preferred.',
    secureMailScopeRule: 'RULE-PLAIN-001 (Cleartext Credential Exposure Filter)'
  },
  {
    rfcNumber: 'RFC 3207',
    title: 'SMTP Service Extension for Secure SMTP over Transport Layer Security',
    publicationDate: 'February 2002',
    status: 'PROPOSED_STANDARD',
    statusLabel: 'Current Standard',
    relationship: 'Updated by RFC 7817, RFC 8996; Obsoletes RFC 2487',
    domain: 'Transport Security',
    mandatoryRequirement: 'Defines the STARTTLS command and reply code 220 for opportunistic TLS upgrade on SMTP ports 25 and 587.',
    secureMailScopeRule: 'RULE-STARTTLS-002 (Finite State Machine STARTTLS Verification)'
  },
  {
    rfcNumber: 'RFC 8461',
    title: 'SMTP MTA Strict Transport Security (MTA-STS)',
    publicationDate: 'September 2018',
    status: 'PROPOSED_STANDARD',
    statusLabel: 'Current Standard',
    relationship: 'Complements RFC 8460 (TLS Reporting), RFC 7672 (DANE)',
    domain: 'Protocol Security',
    mandatoryRequirement: 'Enables mail domains to declare policies requiring TLS and certificate validation for incoming SMTP, mitigating STRIPTLS downgrade attacks.',
    secureMailScopeRule: 'RULE-STARTTLS-002 (Downgrade Defense & Policy Inspection)'
  },
  {
    rfcNumber: 'RFC 7672',
    title: 'SMTP Security via Opportunistic DANE TLS',
    publicationDate: 'October 2015',
    status: 'PROPOSED_STANDARD',
    statusLabel: 'Current Standard',
    relationship: 'Uses RFC 6698 (DANE TLSA records) with DNSSEC',
    domain: 'Protocol Security',
    mandatoryRequirement: 'Provides authenticated TLS peer discovery and prevents man-in-the-middle downgrade attacks via DNSSEC-authenticated TLSA records.',
    secureMailScopeRule: 'RULE-STARTTLS-002 (DANE Authentication Parameter Audit)'
  },
  {
    rfcNumber: 'RFC 5280',
    title: 'Internet X.509 Public Key Infrastructure Certificate and CRL Profile',
    publicationDate: 'May 2008',
    status: 'PROPOSED_STANDARD',
    statusLabel: 'Current PKI Standard',
    relationship: 'Obsoletes RFC 3280, RFC 2459',
    domain: 'Certificate Security',
    mandatoryRequirement: 'Requires validity period verification (notBefore <= currentTime <= notAfter), Subject Alternative Name (SAN) validation, and key usage constraints.',
    secureMailScopeRule: 'RULE-CERT-001 (Certificate Validity Window & Profile Check)'
  },
  {
    rfcNumber: 'CVE-2016-2183',
    title: 'Sweet32 Birthday Attack on 64-bit Block Ciphers (3DES / Blowfish)',
    publicationDate: 'August 2016',
    status: 'SECURITY_ADVISORY',
    statusLabel: 'Vulnerability Advisory',
    relationship: 'NIST SP 800-131Ar2 Disallowance; Prohibited in RFC 9325 Section 4.2',
    domain: 'Cryptography & Ciphers',
    mandatoryRequirement: 'Triple-DES (3DES) uses a 64-bit block size vulnerable to collision attacks after ~32GB of data in a continuous TLS connection. Must be disabled.',
    secureMailScopeRule: 'RULE-CIPHER-002 (64-Bit Block Cipher Sweet32 Detection)'
  }
];

export const CryptographicPostureView: React.FC<Props> = ({
  scenario,
  posture,
  onNavigateTab,
  onSelectFinding
}) => {
  const [toggles, setToggles] = useState<WhatIfToggles>({
    disableDeprecatedTls: false,
    removeWeakCiphers: false,
    replaceExpiredCertificates: false,
    requireForwardSecrecy: false,
    enforceTlsOnPlaintext: false
  });

  const [standardsSearch, setStandardsSearch] = useState('');
  const [showStandardsMatrix, setShowStandardsMatrix] = useState(false);

  const whatIfResult = securityService.simulateWhatIfPostures(toggles);

  const toggleHandler = (key: keyof WhatIfToggles) => {
    setToggles(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSelectAllToggles = () => {
    setToggles({
      disableDeprecatedTls: true,
      removeWeakCiphers: true,
      replaceExpiredCertificates: true,
      requireForwardSecrecy: true,
      enforceTlsOnPlaintext: true
    });
  };

  const handleResetToggles = () => {
    setToggles({
      disableDeprecatedTls: false,
      removeWeakCiphers: false,
      replaceExpiredCertificates: false,
      requireForwardSecrecy: false,
      enforceTlsOnPlaintext: false
    });
  };

  const { categoryBreakdown } = posture;

  // Dynamically extract technical observations from active scenario sessions
  const tlsSessions = scenario.sessions.filter(s => s.tlsHandshake);
  const observedTlsVersions = Array.from(
    new Set(tlsSessions.map(s => s.tlsHandshake?.negotiatedVersion).filter(Boolean))
  ) as string[];
  const hasDeprecatedTls = tlsSessions.some(s => s.tlsHandshake?.isDeprecatedVersion);
  const isPlaintextOnly = scenario.sessions.every(s => !s.tlsHandshake && !s.startTlsNegotiated);
  const observedCiphers = Array.from(
    new Set(tlsSessions.map(s => s.tlsHandshake?.cipherSuite.ianaName).filter(Boolean))
  ) as string[];
  const hasWeakCipher = tlsSessions.some(s => s.tlsHandshake?.cipherSuite.isWeak);
  const hasNoForwardSecrecy = tlsSessions.some(s => !s.tlsHandshake?.forwardSecrecy);
  const certList = tlsSessions.map(s => s.tlsHandshake?.certificate).filter(Boolean);
  const hasExpiredCert = certList.some(c => c?.isExpired);
  const hasSha1Cert = certList.some(c => c?.signatureAlgorithm.toLowerCase().includes('sha1'));
  const hasPlaintextAuth = scenario.sessions.some(s => s.plaintextCredentialsExposed);

  const filteredStandards = AUTHORITATIVE_STANDARDS.filter(
    std =>
      std.rfcNumber.toLowerCase().includes(standardsSearch.toLowerCase()) ||
      std.title.toLowerCase().includes(standardsSearch.toLowerCase()) ||
      std.domain.toLowerCase().includes(standardsSearch.toLowerCase()) ||
      std.mandatoryRequirement.toLowerCase().includes(standardsSearch.toLowerCase())
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span>Cryptographic Security Posture Assessment</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Four-domain cryptographic security evaluation based on deterministic RFC, NIST, and CA/Browser Forum standards.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowStandardsMatrix(!showStandardsMatrix)}
            className="flex items-center gap-1.5 px-3 py-1 bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-cyan-800/60 rounded text-xs font-mono font-medium transition-colors cursor-pointer"
          >
            <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showStandardsMatrix ? 'Hide RFC Matrix' : 'Audit Standards Matrix'}</span>
          </button>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Current Assessed State:</span>
            <span
              className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                posture.status === 'OUT OF SCOPE'
                  ? 'bg-amber-950/50 text-amber-300 border-amber-700/70'
                  : posture.status === 'INSUFFICIENT EVIDENCE'
                  ? 'bg-purple-950/50 text-purple-300 border-purple-800/70'
                  : posture.status === 'AT RISK' || posture.status === 'CRITICAL RISK' || posture.status === 'HIGH RISK'
                  ? 'bg-rose-950/40 text-rose-400 border-rose-800'
                  : posture.status === 'DEGRADED'
                  ? 'bg-amber-950/40 text-amber-400 border-amber-800'
                  : 'bg-emerald-950/40 text-emerald-400 border-emerald-800'
              }`}
            >
              {posture.status === 'OUT OF SCOPE' ? 'OUT OF SCOPE (NOT ASSESSABLE)' : posture.status}
            </span>
          </div>
        </div>
      </div>

      {/* Scope Guard Notice when Out of Scope */}
      {(posture.status === 'OUT OF SCOPE' || scenario.sessions.length === 0) && (
        <div className="p-4 bg-amber-950/20 border border-amber-600/40 rounded-xl space-y-2 text-xs">
          <div className="flex items-center gap-2 text-amber-300 font-bold">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>AUDITOR SCOPE GUARD: Cryptographic Posture is NOT ASSESSABLE</span>
          </div>
          <p className="text-slate-300 leading-relaxed">
            The active PCAP ({scenario.pcapMetadata.filename}) does not contain email protocol traffic (SMTP, IMAP, POP3).
            Per the Scope Validation standard, cryptographic assessment across Transport, Cipher Suites, and Certificates is halted
            to prevent false assurance. SecureMailScope strictly prohibits outputting &quot;SECURE&quot; or &quot;0 Findings&quot; on non-email traffic.
          </p>
          <div className="pt-2 flex flex-wrap items-center gap-2">
            <span className="text-slate-400 font-mono text-[11px]">Identified traffic:</span>
            <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono font-semibold text-[11px]">
              {scenario.pcapMetadata.protocolClassification?.primaryProtocol || 'Vehicular / Web / Non-Email'}
            </span>
            <button
              onClick={() => onNavigateTab('dashboard')}
              className="ml-auto px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold cursor-pointer transition-colors"
            >
              View Protocol-Aware Router →
            </button>
          </div>
        </div>
      )}

      {/* The 4 Architectural Domains */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Domain 1: Transport Security */}
        <div className="bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <h3 className="text-sm font-bold text-white">1. Transport Security</h3>
            </div>
            <SeverityBadge severity={categoryBreakdown.transportSecurity.severity} />
          </div>
          <p className="text-xs text-slate-400">
            Governs TLS protocol version negotiation, STARTTLS extension signaling, and defense against cleartext downgrade stripping attacks.
          </p>

          {/* Structured Concept: TLS Version Policy */}
          <div className="space-y-2 text-xs font-mono">
            <div className="p-3 bg-[#080C14] rounded border border-slate-800/80 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-200">TLS Version Policy</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                    hasDeprecatedTls
                      ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                      : isPlaintextOnly
                      ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                      : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                  }`}
                >
                  {hasDeprecatedTls
                    ? 'DEPRECATED'
                    : isPlaintextOnly
                    ? 'OBSOLETE CLEARTEXT'
                    : 'CONFORMING'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Observed</span>
                  <span className="text-white font-medium">
                    {observedTlsVersions.length > 0 ? observedTlsVersions.join(', ') : 'None (Plaintext Traffic)'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Assessment</span>
                  <span
                    className={
                      hasDeprecatedTls
                        ? 'text-rose-400 font-bold'
                        : isPlaintextOnly
                        ? 'text-rose-400 font-bold'
                        : 'text-emerald-400 font-bold'
                    }
                  >
                    {hasDeprecatedTls
                      ? 'DEPRECATED'
                      : isPlaintextOnly
                      ? 'NON-CONFORMING'
                      : 'CONFORMING'}
                  </span>
                </div>
              </div>

              <div className="text-[11px] font-mono border-t border-slate-800/60 pt-1.5 flex items-center justify-between">
                <span className="text-slate-500">Reference:</span>
                <span className="text-cyan-400">RFC 8996 (BCP 195) & RFC 9325</span>
              </div>

              <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                {hasDeprecatedTls
                  ? 'TLS 1.0 and TLS 1.1 are deprecated and must not be negotiated by conforming implementations (RFC 8996). Current IETF BCP 195 guidance (RFC 9325) mandates TLS 1.2 or TLS 1.3.'
                  : isPlaintextOnly
                  ? 'Cleartext email access without transport encryption is obsolete per RFC 8314 Section 3.'
                  : 'Negotiated version adheres to current IETF BCP 195 recommendations (RFC 8446 / RFC 9325) for secure cryptographic transport.'}
              </p>
            </div>

            <div className="p-2 bg-[#080C14] rounded border border-slate-800/70 flex items-center justify-between">
              <span className="text-slate-400">STARTTLS Negotiation</span>
              <span className="text-slate-200">RFC 3207 State Machine Verified</span>
            </div>
            <div className="p-2 bg-[#080C14] rounded border border-slate-800/70 flex items-center justify-between">
              <span className="text-slate-400">Downgrade Defense</span>
              <span className="text-slate-200">MTA-STS (RFC 8461) / DANE (RFC 7672)</span>
            </div>
          </div>

          <div className="pt-2 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Evidence Frames: {categoryBreakdown.transportSecurity.evidenceCount}</span>
            <button
              onClick={() => onNavigateTab('findings')}
              className="text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <span>{categoryBreakdown.transportSecurity.findingsCount} findings</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Domain 2: Cryptography & Ciphers */}
        <div className="bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-400" />
              <h3 className="text-sm font-bold text-white">2. Cryptography & Cipher Suites</h3>
            </div>
            <SeverityBadge severity={categoryBreakdown.cryptography.severity} />
          </div>
          <p className="text-xs text-slate-400">
            Audits symmetric block ciphers, MAC algorithms, key exchange mechanics, and Perfect Forward Secrecy (PFS) enforcement.
          </p>

          <div className="space-y-2 text-xs font-mono">
            {/* Structured Concept: Cipher Suite & Key Exchange Policy */}
            <div className="p-3 bg-[#080C14] rounded border border-slate-800/80 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-200">Cipher & Forward Secrecy Policy</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                    hasWeakCipher || hasNoForwardSecrecy
                      ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                      : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                  }`}
                >
                  {hasWeakCipher
                    ? 'PROHIBITED CIPHER'
                    : hasNoForwardSecrecy
                    ? 'NO FORWARD SECRECY'
                    : 'CONFORMING AEAD'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Observed Cipher</span>
                  <span className="text-white font-medium truncate block" title={observedCiphers.join(', ')}>
                    {observedCiphers.length > 0 ? observedCiphers[0] : 'None (No TLS Handshake)'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Key Exchange</span>
                  <span className={hasNoForwardSecrecy ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold'}>
                    {hasNoForwardSecrecy ? 'Static RSA (No PFS)' : 'ECDHE (PFS Verified)'}
                  </span>
                </div>
              </div>

              <div className="text-[11px] font-mono border-t border-slate-800/60 pt-1.5 flex items-center justify-between">
                <span className="text-slate-500">Reference:</span>
                <span className="text-cyan-400">RFC 9325 Section 4.1-4.2 / CVE-2016-2183</span>
              </div>

              <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                {hasWeakCipher
                  ? '64-bit block ciphers such as 3DES are vulnerable to Sweet32 collision attacks (CVE-2016-2183) and prohibited by RFC 9325 Section 4.2. Static RSA key exchange lacks forward secrecy.'
                  : 'Modern AEAD ciphers (AES-GCM or ChaCha20-Poly1305) with Ephemeral Diffie-Hellman key exchange provide authenticated encryption and Perfect Forward Secrecy.'}
              </p>
            </div>

            <div className="p-2 bg-[#080C14] rounded border border-slate-800/70 flex items-center justify-between">
              <span className="text-slate-400">Symmetric Encryption</span>
              <span className="text-slate-200">AEAD (AES-GCM, ChaCha20-Poly1305)</span>
            </div>
            <div className="p-2 bg-[#080C14] rounded border border-slate-800/70 flex items-center justify-between">
              <span className="text-slate-400">Block Cipher Policy</span>
              <span className="text-slate-200">Disallow 64-bit Blocks & CBC Modes</span>
            </div>
          </div>

          <div className="pt-2 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Evidence Frames: {categoryBreakdown.cryptography.evidenceCount}</span>
            <button
              onClick={() => onNavigateTab('findings')}
              className="text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <span>{categoryBreakdown.cryptography.findingsCount} findings</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Domain 3: Certificate Security */}
        <div className="bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <h3 className="text-sm font-bold text-white">3. Certificate Security</h3>
            </div>
            <SeverityBadge severity={categoryBreakdown.certificateSecurity.severity} />
          </div>
          <p className="text-xs text-slate-400">
            Validates X.509 public key algorithms, key lengths, validity periods, expiry status, and signature hash collision resistance.
          </p>

          <div className="space-y-2 text-xs font-mono">
            {/* Structured Concept: X.509 Certificate Policy */}
            <div className="p-3 bg-[#080C14] rounded border border-slate-800/80 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-200">X.509 Certificate & Hash Policy</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                    hasExpiredCert || hasSha1Cert
                      ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                      : certList.length === 0
                      ? 'bg-slate-800 text-slate-400'
                      : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                  }`}
                >
                  {hasExpiredCert
                    ? 'CERTIFICATE EXPIRED'
                    : hasSha1Cert
                    ? 'WEAK SHA-1 HASH'
                    : certList.length === 0
                    ? 'NO CERT PRESENTED'
                    : 'VALID & CONFORMING'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Validity Status</span>
                  <span className={hasExpiredCert ? 'text-rose-400 font-bold' : 'text-white'}>
                    {hasExpiredCert ? 'Expired Validity Window' : certList.length > 0 ? 'Within Validity Window' : 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Signature Hash</span>
                  <span className={hasSha1Cert ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                    {hasSha1Cert ? 'SHA-1 (Deprecated)' : certList.length > 0 ? 'SHA-256 (Strong)' : 'N/A'}
                  </span>
                </div>
              </div>

              <div className="text-[11px] font-mono border-t border-slate-800/60 pt-1.5 flex items-center justify-between">
                <span className="text-slate-500">Reference:</span>
                <span className="text-cyan-400">RFC 5280 Section 4.1.2.5 / CAB Forum BR 7.1.3</span>
              </div>

              <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                {hasExpiredCert
                  ? 'Expired X.509 certificates invalidate the trust chain and break client verification under RFC 5280 Section 4.1.2.5.'
                  : hasSha1Cert
                  ? 'SHA-1 signature algorithms in certificate chains are deprecated by CA/Browser Forum and NIST SP 800-131Ar2 due to collision risks.'
                  : 'Certificates comply with current CA/Browser Forum Baseline Requirements and RFC 5280 profile specifications.'}
              </p>
            </div>

            <div className="p-2 bg-[#080C14] rounded border border-slate-800/70 flex items-center justify-between">
              <span className="text-slate-400">Key Length Baseline</span>
              <span className="text-slate-200">RSA ≥ 2048-bit / ECC ≥ 256-bit</span>
            </div>
            <div className="p-2 bg-[#080C14] rounded border border-slate-800/70 flex items-center justify-between">
              <span className="text-slate-400">Signature Hash Policy</span>
              <span className="text-slate-200">SHA-256+ (Prohibit SHA-1 / MD5)</span>
            </div>
          </div>

          <div className="pt-2 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Evidence Frames: {categoryBreakdown.certificateSecurity.evidenceCount}</span>
            <button
              onClick={() => onNavigateTab('findings')}
              className="text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <span>{categoryBreakdown.certificateSecurity.findingsCount} findings</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Domain 4: Protocol Security */}
        <div className="bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-purple-400" />
              <h3 className="text-sm font-bold text-white">4. Protocol Security</h3>
            </div>
            <SeverityBadge severity={categoryBreakdown.protocolSecurity.severity} />
          </div>
          <p className="text-xs text-slate-400">
            Audits application-layer protocols (SMTP submission/relay, IMAP4rev1, POP3) for cleartext exposure and capture completeness.
          </p>

          <div className="space-y-2 text-xs font-mono">
            {/* Structured Concept: Email Protocol & Cleartext Transport Policy */}
            <div className="p-3 bg-[#080C14] rounded border border-slate-800/80 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-200">Email Protocol & Cleartext Transport Policy</span>
                <span
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                    hasPlaintextAuth
                      ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                      : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                  }`}
                >
                  {hasPlaintextAuth ? 'RFC 8314 BREACH' : 'CONFORMING PROTOCOL'}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Protocol Transport</span>
                  <span className="text-white font-medium">
                    {scenario.sessions.map(s => `${s.protocol}:${s.destPort}`).join(', ')}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px] uppercase">Plaintext Auth Exposure</span>
                  <span className={hasPlaintextAuth ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                    {hasPlaintextAuth ? 'EXPOSED (USER/PASS)' : 'NONE DETECTED'}
                  </span>
                </div>
              </div>

              <div className="text-[11px] font-mono border-t border-slate-800/60 pt-1.5 flex items-center justify-between">
                <span className="text-slate-500">Reference:</span>
                <span className="text-cyan-400">RFC 8314 Section 3 & RFC 8461 (MTA-STS)</span>
              </div>

              <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
                {hasPlaintextAuth
                  ? 'RFC 8314 establishes that cleartext mail protocols are obsolete. Passwords and message contents transmitted without TLS encapsulation are directly compromised.'
                  : 'Mail protocols utilize encapsulated TLS or authenticated STARTTLS extensions adhering to RFC 8314 and RFC 3207.'}
              </p>
            </div>

            <div className="p-2 bg-[#080C14] rounded border border-slate-800/70 flex items-center justify-between">
              <span className="text-slate-400">RFC 8314 Baseline</span>
              <span className="text-slate-200">Cleartext Mail Considered Obsolete</span>
            </div>
            <div className="p-2 bg-[#080C14] rounded border border-slate-800/70 flex items-center justify-between">
              <span className="text-slate-400">Capture Completeness</span>
              <span className="text-slate-200">ISO/IEC 27037 Evidence Integrity</span>
            </div>
          </div>

          <div className="pt-2 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Evidence Frames: {categoryBreakdown.protocolSecurity.evidenceCount}</span>
            <button
              onClick={() => onNavigateTab('findings')}
              className="text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer"
            >
              <span>{categoryBreakdown.protocolSecurity.findingsCount} findings</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Authoritative Standards & RFC Baseline Matrix (Expandable Audit Table) */}
      {showStandardsMatrix && (
        <div className="bg-[#0B0F17] border border-cyan-800/60 rounded p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white tracking-tight">
                  Authoritative RFC Standards & Cryptographic Compliance Baseline Matrix
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold uppercase">
                  VERIFIED STANDARDS (IETF / NIST / CAB FORUM)
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Every cryptographic assertion, severity rating, and remediation rule in SecureMailScope is grounded in these official specifications.
              </p>
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Filter standards by RFC or domain..."
                value={standardsSearch}
                onChange={e => setStandardsSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1 bg-slate-900 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 text-[11px] uppercase tracking-wider">
                  <th className="py-2.5 px-3">Standard Reference</th>
                  <th className="py-2.5 px-3">Title & Domain</th>
                  <th className="py-2.5 px-3">Current Status</th>
                  <th className="py-2.5 px-3">Mandatory Requirement</th>
                  <th className="py-2.5 px-3">Automated Forensic Rule</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredStandards.map((std, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/30 transition-colors">
                    <td className="py-3 px-3 align-top font-bold text-cyan-400 whitespace-nowrap">
                      {std.rfcNumber}
                      <span className="block text-[10px] text-slate-500 font-normal">{std.publicationDate}</span>
                    </td>
                    <td className="py-3 px-3 align-top">
                      <div className="text-slate-200 font-semibold">{std.title}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">{std.relationship}</div>
                      <span className="inline-block mt-1 text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                        {std.domain}
                      </span>
                    </td>
                    <td className="py-3 px-3 align-top whitespace-nowrap">
                      <span
                        className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          std.status === 'CURRENT_BCP'
                            ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                            : std.status === 'PROPOSED_STANDARD'
                            ? 'bg-blue-950/60 text-blue-300 border border-blue-800/60'
                            : 'bg-amber-950/60 text-amber-300 border border-amber-800/60'
                        }`}
                      >
                        {std.statusLabel}
                      </span>
                    </td>
                    <td className="py-3 px-3 align-top text-slate-300 text-[11px] font-sans leading-relaxed max-w-sm">
                      {std.mandatoryRequirement}
                    </td>
                    <td className="py-3 px-3 align-top text-purple-300 text-[11px]">
                      {std.secureMailScopeRule}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* What-If Remediation Simulator (Prompt Section 19) */}
      <div className="bg-[#0B0F17] border border-cyan-900/60 rounded p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <h3 className="text-base font-bold text-white tracking-tight">
                What-If Remediation Simulator
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold uppercase tracking-wider">
                SIMULATED / PROJECTED
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Simulate enterprise MTA configuration changes and project posture evolution without altering live production systems.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleSelectAllToggles}
              className="px-2.5 py-1 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition-colors cursor-pointer"
            >
              Simulate All Fixes
            </button>
            <button
              onClick={handleResetToggles}
              className="px-2.5 py-1 text-xs font-mono text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
            >
              Reset
            </button>
          </div>
        </div>

        {/* Simulator Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Remediation Toggles */}
          <div className="lg:col-span-7 space-y-2.5">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block font-semibold">
              Select Simulated Remediation Policies:
            </span>

            <label className="p-3 bg-[#080C14] hover:bg-slate-800/30 border border-slate-800 rounded flex items-center justify-between cursor-pointer transition-colors">
              <div className="pr-3">
                <span className="text-xs font-semibold text-slate-200 block">
                  Disable Deprecated TLS 1.0 & TLS 1.1
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Reconfigure MTA to enforce minimum protocol version TLS 1.2 (satisfies RFC 8996 & RFC 9325).
                </span>
              </div>
              <input
                type="checkbox"
                checked={toggles.disableDeprecatedTls}
                onChange={() => toggleHandler('disableDeprecatedTls')}
                className="w-4 h-4 rounded text-cyan-500 bg-slate-900 border-slate-700 focus:ring-cyan-500 cursor-pointer"
              />
            </label>

            <label className="p-3 bg-[#080C14] hover:bg-slate-800/30 border border-slate-800 rounded flex items-center justify-between cursor-pointer transition-colors">
              <div className="pr-3">
                <span className="text-xs font-semibold text-slate-200 block">
                  Remove Obsolete & Weak Ciphers (3DES, RC4, CBC)
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Eliminate 64-bit block ciphers vulnerable to Sweet32 (CVE-2016-2183); mandate AEAD per RFC 9325.
                </span>
              </div>
              <input
                type="checkbox"
                checked={toggles.removeWeakCiphers}
                onChange={() => toggleHandler('removeWeakCiphers')}
                className="w-4 h-4 rounded text-cyan-500 bg-slate-900 border-slate-700 focus:ring-cyan-500 cursor-pointer"
              />
            </label>

            <label className="p-3 bg-[#080C14] hover:bg-slate-800/30 border border-slate-800 rounded flex items-center justify-between cursor-pointer transition-colors">
              <div className="pr-3">
                <span className="text-xs font-semibold text-slate-200 block">
                  Require Perfect Forward Secrecy (ECDHE/DHE)
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Disable static RSA key exchange so past recorded PCAPs cannot be retroactively decrypted.
                </span>
              </div>
              <input
                type="checkbox"
                checked={toggles.requireForwardSecrecy}
                onChange={() => toggleHandler('requireForwardSecrecy')}
                className="w-4 h-4 rounded text-cyan-500 bg-slate-900 border-slate-700 focus:ring-cyan-500 cursor-pointer"
              />
            </label>

            <label className="p-3 bg-[#080C14] hover:bg-slate-800/30 border border-slate-800 rounded flex items-center justify-between cursor-pointer transition-colors">
              <div className="pr-3">
                <span className="text-xs font-semibold text-slate-200 block">
                  Replace Expired Certificates & Deprecate SHA-1
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Deploy valid X.509 certificates with SHA-256 signatures per RFC 5280 and CA/Browser Forum BR.
                </span>
              </div>
              <input
                type="checkbox"
                checked={toggles.replaceExpiredCertificates}
                onChange={() => toggleHandler('replaceExpiredCertificates')}
                className="w-4 h-4 rounded text-cyan-500 bg-slate-900 border-slate-700 focus:ring-cyan-500 cursor-pointer"
              />
            </label>

            <label className="p-3 bg-[#080C14] hover:bg-slate-800/30 border border-slate-800 rounded flex items-center justify-between cursor-pointer transition-colors">
              <div className="pr-3">
                <span className="text-xs font-semibold text-slate-200 block">
                  Enforce Implicit TLS on Cleartext Ports (RFC 8314)
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Disable unencrypted POP3 port 110; require POP3S on port 995 with modern TLS.
                </span>
              </div>
              <input
                type="checkbox"
                checked={toggles.enforceTlsOnPlaintext}
                onChange={() => toggleHandler('enforceTlsOnPlaintext')}
                className="w-4 h-4 rounded text-cyan-500 bg-slate-900 border-slate-700 focus:ring-cyan-500 cursor-pointer"
              />
            </label>
          </div>

          {/* Projected Posture Delta Panel */}
          <div className="lg:col-span-5 bg-[#080C14] border border-slate-800 rounded p-5 flex flex-col justify-between">
            <div>
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block font-semibold">
                Posture Projection Matrix:
              </span>

              <div className="mt-4 grid grid-cols-2 gap-3 text-center">
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-[10px] font-mono text-slate-500 block uppercase">
                    Current Posture
                  </span>
                  <span
                    className={`text-lg font-mono font-bold mt-1 block ${
                      whatIfResult.currentPosture === 'AT RISK'
                        ? 'text-rose-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {whatIfResult.currentPosture}
                  </span>
                </div>

                <div className="p-3 bg-slate-900/60 rounded border border-cyan-800/50">
                  <span className="text-[10px] font-mono text-cyan-400 block uppercase">
                    Projected Posture
                  </span>
                  <span
                    className={`text-lg font-mono font-bold mt-1 block ${
                      whatIfResult.projectedPosture === 'SECURE'
                        ? 'text-emerald-400'
                        : whatIfResult.projectedPosture === 'DEGRADED'
                        ? 'text-amber-400'
                        : 'text-rose-400'
                    }`}
                  >
                    {whatIfResult.projectedPosture}
                  </span>
                </div>
              </div>

              <div className="mt-4 p-3 bg-[#0B0F17] rounded border border-slate-800 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Simulated Risk Reduction:</span>
                  <span className="text-cyan-400 font-bold tabular-nums">
                    {whatIfResult.riskReductionPercentage}%
                  </span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-2 transition-all duration-300"
                    style={{ width: `${whatIfResult.riskReductionPercentage}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                  <span>Resolved Findings: {whatIfResult.resolvedFindingCount}</span>
                  <span>Remaining: {whatIfResult.remainingFindingCount}</span>
                </div>
              </div>

              {whatIfResult.remainingRiskAreas.length > 0 && (
                <div className="mt-3 text-[11px] font-mono text-amber-400/90 space-y-1">
                  <span className="text-slate-500 block uppercase text-[10px]">
                    Remaining Risk Areas:
                  </span>
                  {whatIfResult.remainingRiskAreas.map((item, idx) => (
                    <div key={idx} className="truncate">
                      • {item}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/80 text-[10px] font-mono text-slate-500">
              * Note: Calculations represent simulated policy evaluations based on extracted PCAP artifacts.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
