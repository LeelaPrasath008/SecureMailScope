/**
 * SecureMailScope - Core Security & Forensic Data Models
 * SIH 2026 Problem Statement 26159
 */

export type ProtocolType = 'SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type EvidenceConfidence = 'COMPLETE' | 'PARTIAL' | 'INSUFFICIENT';

export type EvidenceClass = 'OBSERVED' | 'ASSESSED' | 'POLICY' | 'CONTEXTUAL' | 'AI_ASSISTED';

// Allowed Final Forensic Report States per Section 4 & Golden Forensic Rule:
export type PostureStatus =
  | 'SECURE'
  | 'LOW_RISK'
  | 'MEDIUM_RISK'
  | 'HIGH_RISK'
  | 'CRITICAL_RISK'
  | 'OUT_OF_SCOPE'
  | 'INSUFFICIENT_EVIDENCE'
  | 'NOT_ASSESSABLE'
  | 'AT RISK'
  | 'DEGRADED'
  | 'HIGH RISK'
  | 'CRITICAL RISK'
  | 'OUT OF SCOPE'
  | 'INSUFFICIENT EVIDENCE';

export type AssessmentStatus =
  | 'IN_SCOPE'
  | 'OUT_OF_SCOPE'
  | 'OUT OF SCOPE'
  | 'INSUFFICIENT_EVIDENCE'
  | 'INSUFFICIENT EVIDENCE';

export interface ProtocolClassificationEntry {
  protocol: string;
  packetCount: number;
  percentage: number;
  category: 'EMAIL' | 'WEB' | 'INFRASTRUCTURE' | 'VEHICULAR' | 'REMOTE_ACCESS' | 'UNKNOWN';
}

export interface ProtocolClassificationResult {
  detectedProtocols: ProtocolClassificationEntry[];
  counts: {
    smtp: number;
    smtps: number;
    imap: number;
    imaps: number;
    pop3: number;
    pop3s: number;
    http: number;
    https: number;
    dns: number;
    ssh: number;
    ftp: number;
    icmp: number;
    itsG5: number;
    v2x: number;
    unknown: number;
  };
  totalEmailPackets: number;
  totalNonEmailPackets: number;
  primaryProtocol: string;
  primaryCategory: 'EMAIL' | 'WEB' | 'VEHICULAR' | 'INFRASTRUCTURE' | 'REMOTE_ACCESS' | 'UNKNOWN';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface ScopeValidationResult {
  isEmailInScope: boolean;
  assessmentStatus: AssessmentStatus;
  scopeReason: string;
  securityPosture: PostureStatus;
  riskScore: string;
  routingDecision: {
    targetEngine: 'SecureMailScope Analysis' | 'Web Security Engine' | 'V2X Security Gateway' | 'Manual Protocol Carving';
    routedTrafficType: 'Email Traffic' | 'Web Traffic' | 'Vehicular Traffic (ITS-G5 / V2X)' | 'Unknown Traffic';
    isScopeAccepted: boolean;
    explanation: string;
  };
}

export interface ConfidenceScores {
  protocolConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
  evidenceConfidence: EvidenceConfidence;
  assessmentConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface AnalystTransparencySummary {
  totalPackets: number;
  emailPackets: number;
  smtpSessions: number;
  imapSessions: number;
  pop3Sessions: number;
  tlsSessions?: number;
  detectedProtocolsSummary: string;
  scopeStatus: AssessmentStatus;
  whyConclusionReached: string[];
  chainOfCustodyHash: string;
  confidenceScore: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface HandshakeMessageItem {
  name: string;
  stage: string;
  frameNumber?: number;
  status: 'OBSERVED' | 'DERIVED' | 'UNAVAILABLE';
  description?: string;
  originDetails?: string;
}

export interface PCAPMetadata {
  id: string;
  filename: string;
  sha256: string;
  fileSizeBytes: number;
  captureTimestamp: string;
  analysisTimestamp: string;
  packetCount: number;
  streamCount: number;
  status: 'VERIFIED' | 'ANALYZING' | 'CORRUPTED';
  confidence: EvidenceConfidence;
  confidenceReason?: string;
  capturedInterface?: string;
  notes?: string;
  captureDurationSec?: number;
  totalTcpFlows?: number;
  completeSessionsCount?: number;
  partialSessionsCount?: number;
  truncatedSessionsCount?: number;
  tlsHandshakeCount?: number;
  truncatedHandshakeCount?: number;
  missingPacketsCount?: number;
  sha256VerificationState?: 'COMPUTED' | 'MATCHED_REFERENCE' | 'NO_REFERENCE';
  protocolClassification?: ProtocolClassificationResult;
  scopeValidation?: ScopeValidationResult;
  confidenceScores?: ConfidenceScores;
  analystTransparency?: AnalystTransparencySummary;
}

export interface PipelineStage {
  id: string;
  name: string;
  status: 'completed' | 'processing' | 'pending' | 'warning';
  count?: number;
  processingTimeMs?: number;
  details?: string;
  subSteps?: string[];
}

export interface TLSCipherSuite {
  ianaName: string;
  rfcCode: string;
  keyExchange: string;
  encryption: string;
  mac: string;
  prf?: string;
  forwardSecrecy: boolean;
  isWeak: boolean;
  weaknessReason?: string;
}

export interface X509Certificate {
  serialNumber: string;
  subject: string;
  subjectCommonName: string;
  issuer: string;
  issuerCommonName: string;
  validFrom: string;
  validUntil: string;
  isExpired: boolean;
  daysUntilExpiry: number;
  publicKeyAlgorithm: string;
  keyLengthBits: number;
  signatureAlgorithm: string;
  isWeakKey: boolean;
  isWeakSignature: boolean;
  chainStatus: 'VALID' | 'UNTRUSTED_ROOT' | 'INCOMPLETE_CHAIN' | 'EXPIRED';
  sanList: string[];
  fingerprintSha256: string;
}

export interface TLSHandshake {
  negotiatedVersion: 'TLS 1.0' | 'TLS 1.1' | 'TLS 1.2' | 'TLS 1.3' | 'SSL 3.0' | 'NONE';
  isDeprecatedVersion: boolean;
  cipherSuite: TLSCipherSuite;
  forwardSecrecy: boolean;
  certificate?: X509Certificate;
  alpn?: string;
  sni?: string;
  sessionResumed?: boolean;
  rawRecordHex?: string;
  handshakeMessages?: HandshakeMessageItem[];
}

export interface ProtocolEvent {
  id: string;
  timestamp: string;
  relativeMs: number;
  direction: 'CLIENT_TO_SERVER' | 'SERVER_TO_CLIENT' | 'INTERNAL';
  stage: 'TCP' | 'BANNER' | 'GREETING' | 'STARTTLS' | 'TLS_HANDSHAKE' | 'AUTH' | 'TRANSACTION' | 'TERMINATION';
  title: string;
  payloadPreview?: string;
  isWeaknessOrAnomaly?: boolean;
  detail: string;
  packetNumber: number;
  tcpStreamIndex: number;
}

export interface CryptographicEvidence {
  id: string;
  sessionId: string;
  pcapId: string;
  evidenceType: 'TLS_VERSION' | 'CIPHER_SUITE' | 'CERTIFICATE' | 'STARTTLS_BEHAVIOR' | 'PLAINTEXT_EXPOSURE' | 'KEY_EXCHANGE';
  rawObservation: string;
  packetFrameNumbers: number[];
  byteOffsetHex?: string;
  hexDumpSample?: string;
  confidence: EvidenceConfidence;
  confidenceExplanation: string;
  verifiedTimestamp: string;
  authoritativeStandard?: string;
}

export interface DeterministicRule {
  ruleId: string;
  title: string;
  standardReference: string;
  authoritativeAuthority: string;
  logicExpression: string;
  severityDefault: SeverityLevel;
  description: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: SeverityLevel;
  confidence: EvidenceConfidence;
  affectedSessionId: string;
  evidenceIds: string[];
  ruleId: string;
  ruleTitle: string;
  standardReference: string;
  evidenceStatement: string;
  technicalReason: string;
  securityImpact: string;
  recommendedAction: string;
  priorityOrder: number;
  remediationComplexity: 'LOW' | 'MEDIUM' | 'HIGH';
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED';
  evidenceClass?: EvidenceClass;
  observedValue?: string;
  expectedPolicyValue?: string;
  policyProfile?: string;
  forensicLimitations?: string;
}

export interface EmailSession {
  id: string;
  pcapId: string;
  protocol: ProtocolType;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  serverHostname?: string;
  startTlsAdvertised: boolean;
  startTlsRequested: boolean;
  startTlsNegotiated: boolean;
  tlsHandshake?: TLSHandshake;
  risk: SeverityLevel;
  evidenceConfidence: EvidenceConfidence;
  evidenceConfidenceReason: string;
  durationSec: number;
  timestamp: string;
  findingsIds: string[];
  evidenceIds: string[];
  protocolEvents: ProtocolEvent[];
  bannerText?: string;
  plaintextCredentialsExposed?: boolean;
  clientSoftware?: string;
}

export interface AIReasoningAnalysis {
  sessionId?: string;
  findingId?: string;
  available: boolean;
  groundedEvidenceInput: Record<string, any>;
  contextualAssessment: string;
  interactionImpact: string;
  prioritizedSequence: string[];
  aiConfidence: 'VERY_HIGH' | 'HIGH' | 'MODERATE';
  aiConfidenceBasis: string;
  disclaimer: string;
  suggestedMitigation: string[];
}

export interface SecurityPosture {
  status: PostureStatus;
  overallScoreLabel: string;
  technicalPosture?: PostureStatus;
  policyPosture?: PostureStatus;
  policyProfileName?: string;
  activeViolationsCount?: number;
  policyBasisExplanation?: string;
  portBreakdown?: {
    smtpObservedPorts: number[];
    smtpExpectedPorts: number[];
    imapObservedPorts: number[];
    imapExpectedPorts: number[];
    pop3ObservedPorts: number[];
    pop3ExpectedPorts: number[];
  };
  contributingFactors: {
    label: string;
    severity: SeverityLevel;
    count: number;
    description: string;
  }[];
  assessmentStatus?: AssessmentStatus;
  scopeValidation?: ScopeValidationResult;
  scopeReason?: string;
  isEmailInScope?: boolean;
  confidenceScores?: ConfidenceScores;
  transparencySummary?: AnalystTransparencySummary;
  routingDecision?: ScopeValidationResult['routingDecision'];
  summaryCounts: {
    pcapsAnalyzed: number;
    totalSessions: number;
    smtpSessions: number;
    imapSessions: number;
    pop3Sessions: number;
    tlsSessions: number;
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
  };
  categoryBreakdown: {
    transportSecurity: {
      status: PostureStatus;
      evidenceCount: number;
      findingsCount: number;
      severity: SeverityLevel;
      keyMetric: string;
    };
    cryptography: {
      status: PostureStatus;
      evidenceCount: number;
      findingsCount: number;
      severity: SeverityLevel;
      keyMetric: string;
    };
    certificateSecurity: {
      status: PostureStatus;
      evidenceCount: number;
      findingsCount: number;
      severity: SeverityLevel;
      keyMetric: string;
    };
    protocolSecurity: {
      status: PostureStatus;
      evidenceCount: number;
      findingsCount: number;
      severity: SeverityLevel;
      keyMetric: string;
    };
  };
}

export interface DemoScenario {
  id: string;
  title: string;
  subtitle: string;
  pcapMetadata: PCAPMetadata;
  sessions: EmailSession[];
  findings: Finding[];
  evidenceList: CryptographicEvidence[];
  rules: DeterministicRule[];
  defaultSelectedSessionId: string;
  description: string;
  assessmentStatus?: AssessmentStatus;
  scopeValidation?: ScopeValidationResult;
  confidenceScores?: ConfidenceScores;
  analystTransparency?: AnalystTransparencySummary;
}
