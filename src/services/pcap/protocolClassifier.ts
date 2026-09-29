/**
 * SecureMailScope - Protocol Classification Engine
 * SECTION 1: Identify protocols present in the PCAP before any security assessment.
 * SIH 2026 Problem Statement 26159
 */

import { ParsedPacket } from './pcapTypes';
import { ProtocolClassificationEntry, ProtocolClassificationResult } from '../../types/security';

export function classifyProtocols(packets: ParsedPacket[]): ProtocolClassificationResult {
  const counts = {
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
    itsG5: 0,
    v2x: 0,
    unknown: 0
  };

  for (const pkt of packets) {
    const proto = pkt.detectedAppProtocol;
    const sp = pkt.sourcePort;
    const dp = pkt.destPort;
    const isTls = pkt.detectedAppProtocol === 'TLS';

    if (proto === 'ITS-G5') {
      counts.itsG5++;
    } else if (proto === 'V2X') {
      counts.v2x++;
    } else if (proto === 'SMTPS' || (isTls && (sp === 465 || dp === 465))) {
      counts.smtps++;
    } else if (proto === 'IMAPS' || (isTls && (sp === 993 || dp === 993))) {
      counts.imaps++;
    } else if (proto === 'POP3S' || (isTls && (sp === 995 || dp === 995))) {
      counts.pop3s++;
    } else if (proto === 'SMTP' || sp === 25 || dp === 25 || sp === 587 || dp === 587) {
      counts.smtp++;
    } else if (proto === 'IMAP' || sp === 143 || dp === 143) {
      counts.imap++;
    } else if (proto === 'POP3' || sp === 110 || dp === 110) {
      counts.pop3++;
    } else if (proto === 'HTTPS' || (isTls && (sp === 443 || dp === 443)) || sp === 443 || dp === 443) {
      counts.https++;
    } else if (proto === 'HTTP' || sp === 80 || dp === 80 || sp === 8080 || dp === 8080) {
      counts.http++;
    } else if (proto === 'DNS' || sp === 53 || dp === 53) {
      counts.dns++;
    } else if (proto === 'SSH' || sp === 22 || dp === 22) {
      counts.ssh++;
    } else if (proto === 'FTP' || sp === 21 || dp === 21 || sp === 20 || dp === 20) {
      counts.ftp++;
    } else if (proto === 'ICMP' || pkt.transportProtocol === 'ICMP' || pkt.transportProtocol === 'ICMPv6') {
      counts.icmp++;
    } else {
      counts.unknown++;
    }
  }

  const total = Math.max(1, packets.length);
  const totalEmailPackets = counts.smtp + counts.smtps + counts.imap + counts.imaps + counts.pop3 + counts.pop3s;
  const totalNonEmailPackets = packets.length - totalEmailPackets;

  const rawEntries: { name: string; count: number; category: ProtocolClassificationEntry['category'] }[] = [
    { name: 'SMTP', count: counts.smtp, category: 'EMAIL' },
    { name: 'SMTPS', count: counts.smtps, category: 'EMAIL' },
    { name: 'IMAP', count: counts.imap, category: 'EMAIL' },
    { name: 'IMAPS', count: counts.imaps, category: 'EMAIL' },
    { name: 'POP3', count: counts.pop3, category: 'EMAIL' },
    { name: 'POP3S', count: counts.pop3s, category: 'EMAIL' },
    { name: 'HTTP', count: counts.http, category: 'WEB' },
    { name: 'HTTPS', count: counts.https, category: 'WEB' },
    { name: 'DNS', count: counts.dns, category: 'INFRASTRUCTURE' },
    { name: 'SSH', count: counts.ssh, category: 'REMOTE_ACCESS' },
    { name: 'FTP', count: counts.ftp, category: 'REMOTE_ACCESS' },
    { name: 'ICMP', count: counts.icmp, category: 'INFRASTRUCTURE' },
    { name: 'ITS-G5', count: counts.itsG5, category: 'VEHICULAR' },
    { name: 'V2X', count: counts.v2x, category: 'VEHICULAR' },
    { name: 'Unknown', count: counts.unknown, category: 'UNKNOWN' }
  ];

  const detectedProtocols: ProtocolClassificationEntry[] = rawEntries
    .filter((e) => e.count > 0)
    .map((e) => ({
      protocol: e.name,
      packetCount: e.count,
      percentage: Number(((e.count / total) * 100).toFixed(1)),
      category: e.category
    }))
    .sort((a, b) => b.packetCount - a.packetCount);

  // If no specific protocols identified, keep Unknown as an entry
  if (detectedProtocols.length === 0) {
    detectedProtocols.push({
      protocol: 'Unknown',
      packetCount: packets.length,
      percentage: 100,
      category: 'UNKNOWN'
    });
  }

  // Determine Primary Category & Protocol
  const primaryEntry = detectedProtocols[0];
  const primaryProtocol = primaryEntry?.protocol || 'Unknown';
  const primaryCategory = primaryEntry?.category || 'UNKNOWN';

  // Classification Confidence
  let confidence: 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH';
  if (packets.length === 0) {
    confidence = 'LOW';
  } else if (counts.unknown > packets.length * 0.5) {
    confidence = 'LOW';
  } else if (counts.unknown > packets.length * 0.2) {
    confidence = 'MEDIUM';
  }

  return {
    detectedProtocols,
    counts,
    totalEmailPackets,
    totalNonEmailPackets,
    primaryProtocol,
    primaryCategory,
    confidence
  };
}
