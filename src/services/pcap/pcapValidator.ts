/**
 * SecureMailScope - STEP 7: Validation Test Suite
 * SIH 2026 Problem Statement 26159
 *
 * Verifies exact compliance with the user requirement:
 * If PCAP contains:
 * - 3 ICMP packets
 * - 0 TCP packets
 * - 0 SMTP packets
 * - 0 TLS packets
 * - 1 fragmented IPv4 datagram
 *
 * Dashboard must show:
 * Total Streams = 0
 * SMTP Flows = 0
 * IMAP/POP3 = 0
 * TLS Handshakes = 0
 * Critical Risk = 0
 * Total Findings = 1
 *
 * Finding: IPv4 Fragmentation Observed
 *
 * Must NOT generate TLS, SMTP, certificate, or email findings.
 */

import { executeRealPcapPipeline, PipelineExecutionResult } from './pcapPipeline';

export interface ValidationTestReport {
  testName: string;
  passed: boolean;
  assertions: {
    name: string;
    expected: any;
    actual: any;
    passed: boolean;
  }[];
  pipelineResult: PipelineExecutionResult;
}

/**
 * Constructs a minimal binary PCAP containing:
 * - 2 normal ICMP packets
 * - 1 fragmented IPv4 ICMP packet (MF flag = 1)
 * Total: 3 ICMP packets, 0 TCP, 0 SMTP, 0 TLS, 1 fragmented IPv4 datagram.
 */
export function createSyntheticValidationPcap(): ArrayBuffer {
  // Global header: 24 bytes
  // Each packet: 16 bytes header + 14 bytes Ethernet + 20 bytes IPv4 + 8 bytes ICMP = 58 bytes
  // Total size: 24 + 3 * 58 = 198 bytes
  const buffer = new ArrayBuffer(24 + 3 * 58);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // 1. PCAP Global Header
  view.setUint32(0, 0xa1b2c3d4, false); // Magic number
  view.setUint16(4, 2, false); // Version major 2
  view.setUint16(6, 4, false); // Version minor 4
  view.setUint32(8, 0, false); // Thiszone
  view.setUint32(12, 0, false); // Sigfigs
  view.setUint32(16, 65535, false); // Snaplen
  view.setUint32(20, 1, false); // LinkType = 1 (Ethernet)

  let offset = 24;

  // 3 ICMP packets (Packets 1 and 2: normal ICMP, Packet 3: fragmented IPv4 ICMP)
  for (let i = 1; i <= 3; i++) {
    const isFragmented = i === 3; // Exactly 1 fragmented packet

    // Packet Header (16 bytes)
    view.setUint32(offset, 1700000000 + i, false); // ts_sec
    view.setUint32(offset + 4, i * 1000, false); // ts_usec
    view.setUint32(offset + 8, 42, false); // incl_len: 14 (Eth) + 20 (IP) + 8 (ICMP) = 42 bytes
    view.setUint32(offset + 12, 42, false); // orig_len: 42 bytes
    offset += 16;

    // Ethernet Header (14 bytes)
    // Dest MAC: 00:11:22:33:44:55
    bytes[offset + 0] = 0x00; bytes[offset + 1] = 0x11; bytes[offset + 2] = 0x22;
    bytes[offset + 3] = 0x33; bytes[offset + 4] = 0x44; bytes[offset + 5] = 0x55;
    // Source MAC: 66:77:88:99:aa:bb
    bytes[offset + 6] = 0x66; bytes[offset + 7] = 0x77; bytes[offset + 8] = 0x88;
    bytes[offset + 9] = 0x99; bytes[offset + 10] = 0xaa; bytes[offset + 11] = 0xbb;
    // EtherType: IPv4 (0x0800)
    bytes[offset + 12] = 0x08; bytes[offset + 13] = 0x00;
    offset += 14;

    // IPv4 Header (20 bytes)
    bytes[offset + 0] = 0x45; // Version 4, IHL 5 (20 bytes)
    bytes[offset + 1] = 0x00; // DSCP
    bytes[offset + 2] = 0x00; bytes[offset + 3] = 0x1c; // Total Length: 28 bytes
    bytes[offset + 4] = 0x12; bytes[offset + 5] = 0x34; // Identification: 0x1234

    // Flags & Fragment Offset
    if (isFragmented) {
      // More Fragments (MF) = 1 -> Bit 13 set (0x2000)
      bytes[offset + 6] = 0x20;
      bytes[offset + 7] = 0x00;
    } else {
      // DF = 1 -> Bit 14 set (0x4000)
      bytes[offset + 6] = 0x40;
      bytes[offset + 7] = 0x00;
    }

    bytes[offset + 8] = 64; // TTL
    bytes[offset + 9] = 1; // Protocol: 1 (ICMP)
    bytes[offset + 10] = 0; bytes[offset + 11] = 0; // Checksum placeholder

    // Source IP: 192.168.1.50
    bytes[offset + 12] = 192; bytes[offset + 13] = 168; bytes[offset + 14] = 1; bytes[offset + 15] = 50;
    // Dest IP: 192.168.1.1
    bytes[offset + 16] = 192; bytes[offset + 17] = 168; bytes[offset + 18] = 1; bytes[offset + 19] = 1;
    offset += 20;

    // ICMP Header (8 bytes)
    bytes[offset + 0] = 0x08; // Type: 8 (Echo Request)
    bytes[offset + 1] = 0x00; // Code: 0
    bytes[offset + 2] = 0x00; bytes[offset + 3] = 0x00; // Checksum
    bytes[offset + 4] = 0x00; bytes[offset + 5] = 0x01; // ID
    bytes[offset + 6] = 0x00; bytes[offset + 7] = i; // Sequence
    offset += 8;
  }

  return buffer;
}

export async function runStep7Validation(): Promise<ValidationTestReport> {
  const syntheticBuffer = createSyntheticValidationPcap();
  const result = await executeRealPcapPipeline(syntheticBuffer, 'step7_icmp_fragment_validation.pcap');

  const { metrics, scenario } = result;

  const assertions = [
    {
      name: 'Total Streams == 0',
      expected: 0,
      actual: metrics.totalStreams,
      passed: metrics.totalStreams === 0
    },
    {
      name: 'SMTP Flows == 0',
      expected: 0,
      actual: metrics.smtpFlows,
      passed: metrics.smtpFlows === 0
    },
    {
      name: 'IMAP Flows == 0',
      expected: 0,
      actual: metrics.imapFlows,
      passed: metrics.imapFlows === 0
    },
    {
      name: 'POP3 Flows == 0',
      expected: 0,
      actual: metrics.pop3Flows,
      passed: metrics.pop3Flows === 0
    },
    {
      name: 'TLS Handshakes == 0',
      expected: 0,
      actual: metrics.tlsHandshakes,
      passed: metrics.tlsHandshakes === 0
    },
    {
      name: 'Critical Risk == 0',
      expected: 0,
      actual: metrics.criticalRiskCount,
      passed: metrics.criticalRiskCount === 0
    },
    {
      name: 'Total Findings == 1',
      expected: 1,
      actual: metrics.totalFindings,
      passed: metrics.totalFindings === 1
    },
    {
      name: 'Finding Title is "IPv4 Fragmentation Observed"',
      expected: 'IPv4 Fragmentation Observed',
      actual: scenario.findings[0]?.title,
      passed: scenario.findings[0]?.title === 'IPv4 Fragmentation Observed'
    },
    {
      name: 'Zero TLS Findings Generated',
      expected: true,
      actual: !scenario.findings.some((f) => f.ruleId.startsWith('RULE-TLS')),
      passed: !scenario.findings.some((f) => f.ruleId.startsWith('RULE-TLS'))
    },
    {
      name: 'Zero Certificate Findings Generated',
      expected: true,
      actual: !scenario.findings.some((f) => f.ruleId.startsWith('RULE-CERT')),
      passed: !scenario.findings.some((f) => f.ruleId.startsWith('RULE-CERT'))
    },
    {
      name: 'Zero STARTTLS or Email Findings Generated',
      expected: true,
      actual: !scenario.findings.some((f) => f.ruleId.startsWith('RULE-STARTTLS') || f.ruleId.startsWith('RULE-PLAIN')),
      passed: !scenario.findings.some((f) => f.ruleId.startsWith('RULE-STARTTLS') || f.ruleId.startsWith('RULE-PLAIN'))
    }
  ];

  const allPassed = assertions.every((a) => a.passed);

  return {
    testName: 'STEP 7 – VALIDATION (3 ICMP, 0 TCP, 0 SMTP, 0 TLS, 1 Fragmented IPv4)',
    passed: allPassed,
    assertions,
    pipelineResult: result
  };
}
