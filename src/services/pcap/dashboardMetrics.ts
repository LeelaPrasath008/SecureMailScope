/**
 * SecureMailScope - Dashboard Metrics Calculation
 * STEP 6: Dashboard Metrics
 * SIH 2026 Problem Statement 26159
 */

import { ParsedPacket, RealAnalysisMetrics, ReconstructedFlow } from './pcapTypes';
import { Finding } from '../../types/security';

export function calculateDashboardMetrics(
  packets: ParsedPacket[],
  flows: ReconstructedFlow[],
  findings: Finding[]
): RealAnalysisMetrics {
  // 1. Packet Protocol Counts
  const totalPackets = packets.length;
  const ipv4Count = packets.filter((p) => p.networkProtocol === 'IPv4').length;
  const ipv6Count = packets.filter((p) => p.networkProtocol === 'IPv6').length;
  const tcpCount = packets.filter((p) => p.transportProtocol === 'TCP').length;
  const udpCount = packets.filter((p) => p.transportProtocol === 'UDP').length;
  const icmpCount = packets.filter((p) => p.transportProtocol === 'ICMP' || p.transportProtocol === 'ICMPv6').length;
  const dnsCount = packets.filter((p) => p.detectedAppProtocol === 'DNS').length;

  // 2. Flow Counts
  const totalStreams = flows.length;
  const smtpFlows = flows.filter((f) => f.protocol === 'SMTP').length;
  const imapFlows = flows.filter((f) => f.protocol === 'IMAP').length;
  const pop3Flows = flows.filter((f) => f.protocol === 'POP3').length;

  // 3. TLS Handshake Counts
  // Only count flows where a TLS handshake was actually observed!
  const tlsHandshakes = flows.filter((f) => f.hasTls && f.tlsVersion != null).length;

  // 4. Finding Risk Counts
  const criticalRiskCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highRiskCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumRiskCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowRiskCount = findings.filter((f) => f.severity === 'LOW').length;
  const totalFindings = findings.length;

  return {
    totalPackets,
    ipv4Count,
    ipv6Count,
    tcpCount,
    udpCount,
    icmpCount,
    dnsCount,
    totalStreams,
    smtpFlows,
    imapFlows,
    pop3Flows,
    tlsHandshakes,
    criticalRiskCount,
    highRiskCount,
    mediumRiskCount,
    lowRiskCount,
    totalFindings
  };
}
