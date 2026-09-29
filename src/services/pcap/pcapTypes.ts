/**
 * SecureMailScope - PCAP Engine Data Types
 * SIH 2026 Problem Statement 26159
 */

export interface ParsedPacket {
  frameNumber: number;
  timestampSec: number;
  timestampUsec: number;
  timestampFormatted: string;
  capturedLength: number;
  originalLength: number;
  linkType: number;
  networkProtocol: 'IPv4' | 'IPv6' | 'ARP' | 'OTHER';
  sourceIp: string;
  destIp: string;
  // IPv4 Fragmentation (Rule 6)
  ipv4Fragmented: boolean;
  ipv4MoreFragments: boolean;
  ipv4FragmentOffset: number;
  ipv4Identification?: number;
  // Transport Layer
  transportProtocol: 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'OTHER';
  sourcePort: number;
  destPort: number;
  tcpFlags?: {
    syn: boolean;
    ack: boolean;
    fin: boolean;
    rst: boolean;
    psh: boolean;
    urg: boolean;
  };
  seqNumber?: number;
  ackNumber?: number;
  payloadOffset: number;
  payloadLength: number;
  payload: Uint8Array;
  hexDumpPreview: string;
  detectedAppProtocol:
    | 'SMTP'
    | 'SMTPS'
    | 'IMAP'
    | 'IMAPS'
    | 'POP3'
    | 'POP3S'
    | 'HTTP'
    | 'HTTPS'
    | 'DNS'
    | 'SSH'
    | 'FTP'
    | 'ICMP'
    | 'ITS-G5'
    | 'V2X'
    | 'TLS'
    | 'UNKNOWN'
    | 'NONE';
}

export interface ReconstructedFlow {
  flowKey: string;
  streamIndex: number;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  protocol: 'SMTP' | 'IMAP' | 'POP3' | 'TCP' | 'UDP' | 'ICMP' | 'OTHER';
  packetCount: number;
  byteCount: number;
  startSec: number;
  endSec: number;
  durationSec: number;
  packets: ParsedPacket[];
  // TCP & Email protocol analysis
  startTlsAdvertised: boolean;
  startTlsRequested: boolean;
  startTlsNegotiated: boolean;
  plaintextCredentialsExposed: boolean;
  exposedCredentialsDetails?: string;
  clientCommands: string[];
  serverResponses: string[];
  serverBanner?: string;
  serverHostname?: string;
  // TLS Handshake details
  hasTls: boolean;
  tlsVersion?: 'TLS 1.0' | 'TLS 1.1' | 'TLS 1.2' | 'TLS 1.3';
  tlsVersionCode?: number;
  cipherSuiteCode?: number;
  cipherSuiteName?: string;
  cipherSuiteIsWeak?: boolean;
  cipherSuiteKeyExchange?: string;
  forwardSecrecy?: boolean;
  certificatePresented?: boolean;
  certificateIssuer?: string;
  certificateSubject?: string;
  certificateSanList?: string[];
  certificateExpirationDate?: string;
  certificateIsExpired?: boolean;
  certificateIsSelfSigned?: boolean;
  certificateSignatureAlgo?: string;
  certificateSerialNumber?: string;
}

export interface RealAnalysisMetrics {
  totalPackets: number;
  ipv4Count: number;
  ipv6Count: number;
  tcpCount: number;
  udpCount: number;
  icmpCount: number;
  dnsCount: number;
  // Step 6 Metrics
  totalStreams: number;
  smtpFlows: number;
  imapFlows: number;
  pop3Flows: number;
  tlsHandshakes: number;
  criticalRiskCount: number;
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  totalFindings: number;
}
