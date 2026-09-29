/**
 * SecureMailScope - PCAP & PCAPNG Binary Parser
 * STEP 1: PCAP Parsing
 * SIH 2026 Problem Statement 26159
 */

import { ParsedPacket } from './pcapTypes';

export function bytesToHexPreview(bytes: Uint8Array, maxBytes = 48): string {
  const slice = bytes.slice(0, Math.min(bytes.length, maxBytes));
  const hexParts: string[] = [];
  for (let i = 0; i < slice.length; i++) {
    hexParts.push(slice[i].toString(16).padStart(2, '0'));
  }
  return hexParts.join(' ') + (bytes.length > maxBytes ? ' ...' : '');
}

export function parsePcapBuffer(buffer: ArrayBuffer): {
  packets: ParsedPacket[];
  format: 'PCAP' | 'PCAPNG' | 'UNKNOWN';
  error?: string;
} {
  const dataView = new DataView(buffer);
  if (buffer.byteLength < 24) {
    return { packets: [], format: 'UNKNOWN', error: 'File is too small to be a valid PCAP.' };
  }

  const magic = dataView.getUint32(0, false);

  // Check for PCAPNG (0x0A0D0D0A)
  if (magic === 0x0a0d0d0a) {
    return parsePcapNg(buffer);
  }

  // Check for classic PCAP
  // 0xa1b2c3d4 (microsecond standard), 0xd4c3b2a1 (swapped)
  // 0xa1b23c4d (nanosecond standard), 0x4d3cb2a1 (swapped)
  let littleEndian = true;
  let isNanosecond = false;

  if (magic === 0xa1b2c3d4) {
    littleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    littleEndian = true;
  } else if (magic === 0xa1b23c4d) {
    littleEndian = false;
    isNanosecond = true;
  } else if (magic === 0x4d3cb2a1) {
    littleEndian = true;
    isNanosecond = true;
  } else {
    // Attempt fallback heuristic parsing
    return parsePcapNg(buffer);
  }

  const linkType = dataView.getUint32(20, littleEndian);
  let offset = 24;
  const packets: ParsedPacket[] = [];
  let frameNumber = 1;

  while (offset + 16 <= buffer.byteLength) {
    const tsSec = dataView.getUint32(offset, littleEndian);
    const tsUsec = dataView.getUint32(offset + 4, littleEndian);
    const inclLen = dataView.getUint32(offset + 8, littleEndian);
    const origLen = dataView.getUint32(offset + 12, littleEndian);
    offset += 16;

    if (inclLen > 65535 || offset + inclLen > buffer.byteLength) {
      // Packet truncated or malformed boundary
      break;
    }

    const packetBytes = new Uint8Array(buffer, offset, inclLen);
    const parsed = parsePacketData(
      packetBytes,
      frameNumber,
      tsSec,
      isNanosecond ? Math.floor(tsUsec / 1000) : tsUsec,
      origLen,
      linkType
    );

    packets.push(parsed);
    frameNumber++;
    offset += inclLen;
  }

  return { packets, format: 'PCAP' };
}

function parsePcapNg(buffer: ArrayBuffer): {
  packets: ParsedPacket[];
  format: 'PCAPNG';
  error?: string;
} {
  const dataView = new DataView(buffer);
  let offset = 0;
  let littleEndian = true;
  const packets: ParsedPacket[] = [];
  let frameNumber = 1;
  const interfaceLinkTypes: number[] = [];

  while (offset + 8 <= buffer.byteLength) {
    const blockType = dataView.getUint32(offset, littleEndian);
    const blockTotalLength = dataView.getUint32(offset + 4, littleEndian);

    if (blockTotalLength < 12 || offset + blockTotalLength > buffer.byteLength) {
      break;
    }

    // Section Header Block (0x0A0D0D0A)
    if (blockType === 0x0a0d0d0a) {
      if (offset + 12 <= buffer.byteLength) {
        const byteOrderMagic = dataView.getUint32(offset + 8, false);
        littleEndian = byteOrderMagic !== 0x1a2b3c4d;
      }
    }
    // Interface Description Block (0x00000001)
    else if (blockType === 0x00000001) {
      if (offset + 12 <= buffer.byteLength) {
        const linkType = dataView.getUint16(offset + 8, littleEndian);
        interfaceLinkTypes.push(linkType);
      }
    }
    // Enhanced Packet Block (0x00000006)
    else if (blockType === 0x00000006) {
      if (offset + 28 <= buffer.byteLength) {
        const interfaceId = dataView.getUint32(offset + 8, littleEndian);
        const linkType = interfaceLinkTypes[interfaceId] ?? 1; // default Ethernet
        const tsHigh = dataView.getUint32(offset + 12, littleEndian);
        const tsLow = dataView.getUint32(offset + 16, littleEndian);
        const capLen = dataView.getUint32(offset + 20, littleEndian);
        const origLen = dataView.getUint32(offset + 24, littleEndian);

        // Calculate timestamp (PCAPNG typically defaults to 10^-6 s)
        const tsRaw = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
        const tsSec = Number(tsRaw / 1000000n);
        const tsUsec = Number(tsRaw % 1000000n);

        const packetDataOffset = offset + 28;
        if (packetDataOffset + capLen <= buffer.byteLength) {
          const packetBytes = new Uint8Array(buffer, packetDataOffset, capLen);
          const parsed = parsePacketData(
            packetBytes,
            frameNumber,
            tsSec || 1700000000,
            tsUsec,
            origLen,
            linkType
          );
          packets.push(parsed);
          frameNumber++;
        }
      }
    }
    // Simple Packet Block (0x00000003)
    else if (blockType === 0x00000003) {
      if (offset + 16 <= buffer.byteLength) {
        const origLen = dataView.getUint32(offset + 8, littleEndian);
        const capLen = Math.min(origLen, blockTotalLength - 16);
        const packetBytes = new Uint8Array(buffer, offset + 12, capLen);
        const parsed = parsePacketData(packetBytes, frameNumber, 1700000000, 0, origLen, 1);
        packets.push(parsed);
        frameNumber++;
      }
    }

    offset += blockTotalLength;
  }

  return { packets, format: 'PCAPNG' };
}

function parsePacketData(
  bytes: Uint8Array,
  frameNumber: number,
  tsSec: number,
  tsUsec: number,
  origLen: number,
  linkType: number
): ParsedPacket {
  let offset = 0;
  let networkProtocol: 'IPv4' | 'IPv6' | 'ARP' | 'OTHER' = 'OTHER';
  let isItsG5 = false;
  let isV2x = false;

  // Link Layer Header handling
  if (linkType === 1) {
    // Ethernet II (14 bytes)
    if (bytes.length >= 14) {
      let etherType = (bytes[12] << 8) | bytes[13];
      offset = 14;

      // 802.1Q VLAN Tagging (4 bytes)
      if (etherType === 0x8100 && bytes.length >= 18) {
        etherType = (bytes[16] << 8) | bytes[17];
        offset = 18;
      }

      if (etherType === 0x0800) {
        networkProtocol = 'IPv4';
      } else if (etherType === 0x86dd) {
        networkProtocol = 'IPv6';
      } else if (etherType === 0x0806) {
        networkProtocol = 'ARP';
      } else if (etherType === 0x8947) {
        // ETSI GeoNetworking / ITS-G5 (Vehicular V2X)
        networkProtocol = 'OTHER';
        isItsG5 = true;
      } else if (etherType === 0x88dc) {
        // IEEE 1609.3 WSMP / WAVE / V2X
        networkProtocol = 'OTHER';
        isV2x = true;
      }
    }
  } else if (linkType === 113) {
    // Linux "cooked" capture SLL (16 bytes)
    if (bytes.length >= 16) {
      const protoType = (bytes[14] << 8) | bytes[15];
      offset = 16;
      if (protoType === 0x0800) networkProtocol = 'IPv4';
      else if (protoType === 0x86dd) networkProtocol = 'IPv6';
      else if (protoType === 0x0806) networkProtocol = 'ARP';
      else if (protoType === 0x8947) {
        networkProtocol = 'OTHER';
        isItsG5 = true;
      } else if (protoType === 0x88dc) {
        networkProtocol = 'OTHER';
        isV2x = true;
      }
    }
  } else if (linkType === 12 || linkType === 101) {
    // Raw IP
    if (bytes.length > 0) {
      const ver = (bytes[0] >> 4) & 0x0f;
      if (ver === 4) networkProtocol = 'IPv4';
      else if (ver === 6) networkProtocol = 'IPv6';
    }
  } else {
    // Heuristic detect IPv4 or IPv6
    if (bytes.length >= 20 && ((bytes[0] >> 4) & 0x0f) === 4) {
      networkProtocol = 'IPv4';
    } else if (bytes.length >= 14 && ((bytes[14] >> 4) & 0x0f) === 4) {
      offset = 14;
      networkProtocol = 'IPv4';
    }
  }

  // Network & Transport Defaults
  let sourceIp = '0.0.0.0';
  let destIp = '0.0.0.0';
  let transportProtocol: 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'OTHER' = 'OTHER';
  let sourcePort = 0;
  let destPort = 0;
  let ipv4Fragmented = false;
  let ipv4MoreFragments = false;
  let ipv4FragmentOffset = 0;
  let ipv4Identification: number | undefined;
  let tcpFlags: ParsedPacket['tcpFlags'];
  let seqNumber: number | undefined;
  let ackNumber: number | undefined;
  let payloadOffset = bytes.length;
  let payloadLength = 0;

  // IPv4 Parsing
  if (networkProtocol === 'IPv4' && bytes.length >= offset + 20) {
    const ihl = (bytes[offset] & 0x0f) * 4;
    const ipTotalLen = (bytes[offset + 2] << 8) | bytes[offset + 3];
    ipv4Identification = (bytes[offset + 4] << 8) | bytes[offset + 5];
    const flagsAndOffset = (bytes[offset + 6] << 8) | bytes[offset + 7];

    // RULE 6: IPv4 Fragmentation Detection
    ipv4MoreFragments = (flagsAndOffset & 0x2000) !== 0;
    ipv4FragmentOffset = (flagsAndOffset & 0x1fff) * 8;
    ipv4Fragmented = ipv4MoreFragments || ipv4FragmentOffset > 0;

    const ipProto = bytes[offset + 9];
    sourceIp = `${bytes[offset + 12]}.${bytes[offset + 13]}.${bytes[offset + 14]}.${bytes[offset + 15]}`;
    destIp = `${bytes[offset + 16]}.${bytes[offset + 17]}.${bytes[offset + 18]}.${bytes[offset + 19]}`;

    const transportOffset = offset + ihl;

    if (ipProto === 1) {
      transportProtocol = 'ICMP';
      payloadOffset = transportOffset;
      payloadLength = Math.max(0, bytes.length - transportOffset);
    } else if (ipProto === 6 && bytes.length >= transportOffset + 20) {
      transportProtocol = 'TCP';
      sourcePort = (bytes[transportOffset] << 8) | bytes[transportOffset + 1];
      destPort = (bytes[transportOffset + 2] << 8) | bytes[transportOffset + 3];
      seqNumber =
        ((bytes[transportOffset + 4] << 24) |
          (bytes[transportOffset + 5] << 16) |
          (bytes[transportOffset + 6] << 8) |
          bytes[transportOffset + 7]) >>>
        0;
      ackNumber =
        ((bytes[transportOffset + 8] << 24) |
          (bytes[transportOffset + 9] << 16) |
          (bytes[transportOffset + 10] << 8) |
          bytes[transportOffset + 11]) >>>
        0;

      const tcpDataOffset = ((bytes[transportOffset + 12] >> 4) & 0x0f) * 4;
      const flagsByte = bytes[transportOffset + 13];

      tcpFlags = {
        fin: (flagsByte & 0x01) !== 0,
        syn: (flagsByte & 0x02) !== 0,
        rst: (flagsByte & 0x04) !== 0,
        psh: (flagsByte & 0x08) !== 0,
        ack: (flagsByte & 0x10) !== 0,
        urg: (flagsByte & 0x20) !== 0
      };

      payloadOffset = transportOffset + tcpDataOffset;
      payloadLength = Math.max(0, bytes.length - payloadOffset);
    } else if (ipProto === 17 && bytes.length >= transportOffset + 8) {
      transportProtocol = 'UDP';
      sourcePort = (bytes[transportOffset] << 8) | bytes[transportOffset + 1];
      destPort = (bytes[transportOffset + 2] << 8) | bytes[transportOffset + 3];
      payloadOffset = transportOffset + 8;
      payloadLength = Math.max(0, bytes.length - payloadOffset);
    }
  }
  // IPv6 Parsing
  else if (networkProtocol === 'IPv6' && bytes.length >= offset + 40) {
    const nextHeader = bytes[offset + 6];
    const srcParts: string[] = [];
    const dstParts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      srcParts.push(((bytes[offset + 8 + i] << 8) | bytes[offset + 9 + i]).toString(16));
      dstParts.push(((bytes[offset + 24 + i] << 8) | bytes[offset + 25 + i]).toString(16));
    }
    sourceIp = srcParts.join(':');
    destIp = dstParts.join(':');

    const transportOffset = offset + 40;
    if (nextHeader === 6 && bytes.length >= transportOffset + 20) {
      transportProtocol = 'TCP';
      sourcePort = (bytes[transportOffset] << 8) | bytes[transportOffset + 1];
      destPort = (bytes[transportOffset + 2] << 8) | bytes[transportOffset + 3];
      const tcpDataOffset = ((bytes[transportOffset + 12] >> 4) & 0x0f) * 4;
      payloadOffset = transportOffset + tcpDataOffset;
      payloadLength = Math.max(0, bytes.length - payloadOffset);
    } else if (nextHeader === 17 && bytes.length >= transportOffset + 8) {
      transportProtocol = 'UDP';
      sourcePort = (bytes[transportOffset] << 8) | bytes[transportOffset + 1];
      destPort = (bytes[transportOffset + 2] << 8) | bytes[transportOffset + 3];
      payloadOffset = transportOffset + 8;
      payloadLength = Math.max(0, bytes.length - payloadOffset);
    } else if (nextHeader === 58) {
      transportProtocol = 'ICMPv6';
      payloadOffset = transportOffset;
      payloadLength = Math.max(0, bytes.length - transportOffset);
    }
  }

  const payload = payloadLength > 0 ? bytes.slice(payloadOffset, payloadOffset + payloadLength) : new Uint8Array(0);

  // App Protocol Detection
  let detectedAppProtocol: ParsedPacket['detectedAppProtocol'] = 'NONE';
  if (isItsG5 || sourcePort === 2001 || destPort === 2001 || sourcePort === 2002 || destPort === 2002 || sourcePort === 2003 || destPort === 2003) {
    detectedAppProtocol = 'ITS-G5';
  } else if (isV2x) {
    detectedAppProtocol = 'V2X';
  } else if (transportProtocol === 'ICMP' || transportProtocol === 'ICMPv6') {
    detectedAppProtocol = 'ICMP';
  } else if (sourcePort === 53 || destPort === 53) {
    detectedAppProtocol = 'DNS';
  } else if (sourcePort === 22 || destPort === 22) {
    detectedAppProtocol = 'SSH';
  } else if (sourcePort === 21 || destPort === 21 || sourcePort === 20 || destPort === 20) {
    detectedAppProtocol = 'FTP';
  } else if (sourcePort === 80 || destPort === 80 || sourcePort === 8080 || destPort === 8080) {
    detectedAppProtocol = 'HTTP';
  } else if (sourcePort === 443 || destPort === 443) {
    detectedAppProtocol = 'HTTPS';
  } else if (sourcePort === 465 || destPort === 465) {
    detectedAppProtocol = 'SMTPS';
  } else if (sourcePort === 25 || destPort === 25 || sourcePort === 587 || destPort === 587) {
    detectedAppProtocol = 'SMTP';
  } else if (sourcePort === 993 || destPort === 993) {
    detectedAppProtocol = 'IMAPS';
  } else if (sourcePort === 143 || destPort === 143) {
    detectedAppProtocol = 'IMAP';
  } else if (sourcePort === 995 || destPort === 995) {
    detectedAppProtocol = 'POP3S';
  } else if (sourcePort === 110 || destPort === 110) {
    detectedAppProtocol = 'POP3';
  }

  // Deep Packet Inspection for TLS Records (Content-Type 0x14 - 0x17)
  if (payload.length >= 5) {
    const ct = payload[0];
    const major = payload[1];
    const minor = payload[2];
    if ((ct >= 0x14 && ct <= 0x17) && (major === 0x03 && minor <= 0x04)) {
      detectedAppProtocol = 'TLS';
    }
  }

  // Deep Packet Inspection for text email commands if on non-standard ports
  if (detectedAppProtocol === 'NONE' && payload.length > 3) {
    const textSample = new TextDecoder('ascii', { fatal: false }).decode(payload.slice(0, 60));
    if (textSample.startsWith('220 ') || textSample.startsWith('EHLO') || textSample.startsWith('HELO') || textSample.includes('STARTTLS')) {
      detectedAppProtocol = 'SMTP';
    } else if (textSample.startsWith('* OK') || textSample.includes('LOGIN') || textSample.includes('CAPABILITY')) {
      detectedAppProtocol = 'IMAP';
    } else if (textSample.startsWith('+OK') || textSample.startsWith('USER ') || textSample.startsWith('PASS ')) {
      detectedAppProtocol = 'POP3';
    }
  }

  // Format timestamp (HH:MM:SS.mmm)
  const d = new Date(tsSec * 1000);
  const timeFormatted = `${d.getUTCHours().toString().padStart(2, '0')}:${d
    .getUTCMinutes()
    .toString()
    .padStart(2, '0')}:${d.getUTCSeconds().toString().padStart(2, '0')}.${Math.floor(tsUsec / 1000)
    .toString()
    .padStart(3, '0')}`;

  return {
    frameNumber,
    timestampSec: tsSec,
    timestampUsec: tsUsec,
    timestampFormatted: timeFormatted,
    capturedLength: bytes.length,
    originalLength: origLen,
    linkType,
    networkProtocol,
    sourceIp,
    destIp,
    ipv4Fragmented,
    ipv4MoreFragments,
    ipv4FragmentOffset,
    ipv4Identification,
    transportProtocol,
    sourcePort,
    destPort,
    tcpFlags,
    seqNumber,
    ackNumber,
    payloadOffset,
    payloadLength,
    payload,
    hexDumpPreview: bytesToHexPreview(payload.length > 0 ? payload : bytes),
    detectedAppProtocol
  };
}
