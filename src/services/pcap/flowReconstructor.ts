/**
 * SecureMailScope - Flow Reconstruction
 * STEP 2: Reconstruct TCP Sessions using (source_ip, source_port, destination_ip, destination_port)
 * SIH 2026 Problem Statement 26159
 */

import { ParsedPacket, ReconstructedFlow } from './pcapTypes';

export function reconstructFlows(packets: ParsedPacket[]): ReconstructedFlow[] {
  const flowMap = new Map<string, ReconstructedFlow>();
  let nextStreamIndex = 0;

  for (const pkt of packets) {
    // Only reconstruct transport layer flows (TCP primarily, or UDP)
    if (pkt.transportProtocol !== 'TCP' && pkt.transportProtocol !== 'UDP') {
      continue;
    }

    // Bidirectional 4-tuple canonical key:
    // Sort endpoints so client->server and server->client map to the exact same stream
    const ip1 = pkt.sourceIp;
    const p1 = pkt.sourcePort;
    const ip2 = pkt.destIp;
    const p2 = pkt.destPort;

    let canonicalKey: string;
    let clientIp: string;
    let clientPort: number;
    let serverIp: string;
    let serverPort: number;

    // Standard mail/TLS ports heuristic or SYN initiator
    const isServerPort = (port: number) => [25, 587, 465, 143, 993, 110, 995, 443, 80, 53].includes(port);

    if (isServerPort(p2) && !isServerPort(p1)) {
      clientIp = ip1;
      clientPort = p1;
      serverIp = ip2;
      serverPort = p2;
    } else if (isServerPort(p1) && !isServerPort(p2)) {
      clientIp = ip2;
      clientPort = p2;
      serverIp = ip1;
      serverPort = p1;
    } else if (pkt.tcpFlags?.syn && !pkt.tcpFlags?.ack) {
      // SYN without ACK = Client initiating connection
      clientIp = ip1;
      clientPort = p1;
      serverIp = ip2;
      serverPort = p2;
    } else {
      // Lexicographical ordering
      if (ip1 < ip2 || (ip1 === ip2 && p1 <= p2)) {
        clientIp = ip1;
        clientPort = p1;
        serverIp = ip2;
        serverPort = p2;
      } else {
        clientIp = ip2;
        clientPort = p2;
        serverIp = ip1;
        serverPort = p1;
      }
    }

    canonicalKey = `${pkt.transportProtocol}:${clientIp}:${clientPort}<->${serverIp}:${serverPort}`;

    let flow = flowMap.get(canonicalKey);
    if (!flow) {
      // Determine protocol strictly from actual ports and packets
      let flowProtocol: ReconstructedFlow['protocol'] = 'TCP';
      const sp = clientPort;
      const dp = serverPort;

      if ([25, 587, 465].includes(dp) || [25, 587, 465].includes(sp)) {
        flowProtocol = 'SMTP';
      } else if ([143, 993].includes(dp) || [143, 993].includes(sp)) {
        flowProtocol = 'IMAP';
      } else if ([110, 995].includes(dp) || [110, 995].includes(sp)) {
        flowProtocol = 'POP3';
      } else if (pkt.transportProtocol === 'UDP') {
        flowProtocol = 'UDP';
      }

      flow = {
        flowKey: canonicalKey,
        streamIndex: nextStreamIndex++,
        sourceIp: clientIp,
        sourcePort: clientPort,
        destIp: serverIp,
        destPort: serverPort,
        clientIp,
        clientPort,
        serverIp,
        serverPort,
        protocol: flowProtocol,
        packetCount: 0,
        byteCount: 0,
        startSec: pkt.timestampSec,
        endSec: pkt.timestampSec,
        durationSec: 0,
        packets: [],
        startTlsAdvertised: false,
        startTlsRequested: false,
        startTlsNegotiated: false,
        plaintextCredentialsExposed: false,
        clientCommands: [],
        serverResponses: [],
        hasTls: false
      };

      flowMap.set(canonicalKey, flow);
    }

    flow.packets.push(pkt);
    flow.packetCount++;
    flow.byteCount += pkt.capturedLength;
    flow.endSec = Math.max(flow.endSec, pkt.timestampSec);
    flow.durationSec = Math.max(0.001, Number((flow.endSec - flow.startSec).toFixed(3)));

    // Update protocol if deeper inspection detected email protocol
    if (flow.protocol === 'TCP') {
      if (pkt.detectedAppProtocol === 'SMTP') flow.protocol = 'SMTP';
      else if (pkt.detectedAppProtocol === 'IMAP') flow.protocol = 'IMAP';
      else if (pkt.detectedAppProtocol === 'POP3') flow.protocol = 'POP3';
    }

    // Check if packet carries TLS record
    if (pkt.detectedAppProtocol === 'TLS') {
      flow.hasTls = true;
    }
  }

  return Array.from(flowMap.values());
}
