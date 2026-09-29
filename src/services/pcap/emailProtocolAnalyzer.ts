/**
 * SecureMailScope - Email Protocol Analyzer
 * STEP 4: Email Protocol Analysis (SMTP, IMAP, POP3)
 * SIH 2026 Problem Statement 26159
 */

import { ReconstructedFlow } from './pcapTypes';

export function analyzeEmailProtocols(flow: ReconstructedFlow): void {
  // Decode ASCII payloads across the stream
  for (const pkt of flow.packets) {
    if (pkt.payloadLength === 0) continue;

    // Skip encrypted binary TLS application data (Content-Type 0x17)
    if (pkt.payload[0] === 0x17 && pkt.payload[1] === 0x03) {
      continue;
    }

    const text = new TextDecoder('ascii', { fatal: false }).decode(pkt.payload);
    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);

    const isClient = pkt.sourceIp === flow.clientIp && pkt.sourcePort === flow.clientPort;

    for (const line of lines) {
      const upper = line.toUpperCase();

      // Track Client Commands
      if (isClient) {
        flow.clientCommands.push(line);

        // SMTP Commands
        if (upper.startsWith('HELO') || upper.startsWith('EHLO')) {
          flow.protocol = 'SMTP';
        } else if (upper === 'STARTTLS') {
          flow.startTlsRequested = true;
          flow.protocol = 'SMTP';
        } else if (upper.startsWith('MAIL FROM:') || upper.startsWith('RCPT TO:')) {
          flow.protocol = 'SMTP';
        } else if (upper.startsWith('AUTH PLAIN') || upper.startsWith('AUTH LOGIN')) {
          flow.protocol = 'SMTP';
          if (!flow.hasTls) {
            flow.plaintextCredentialsExposed = true;
            flow.exposedCredentialsDetails = `SMTP Authentication command transmitted in cleartext on port ${flow.destPort}`;
          }
        }

        // IMAP Commands
        else if (upper.includes('STARTTLS')) {
          flow.startTlsRequested = true;
          flow.protocol = 'IMAP';
        } else if (upper.includes('LOGIN ') || upper.includes('AUTHENTICATE ')) {
          flow.protocol = 'IMAP';
          if (!flow.hasTls) {
            flow.plaintextCredentialsExposed = true;
            flow.exposedCredentialsDetails = `IMAP LOGIN command transmitted in cleartext without TLS on port ${flow.destPort}`;
          }
        }

        // POP3 Commands
        else if (upper.startsWith('STLS')) {
          flow.startTlsRequested = true;
          flow.protocol = 'POP3';
        } else if (upper.startsWith('USER ') || upper.startsWith('PASS ')) {
          flow.protocol = 'POP3';
          if (!flow.hasTls) {
            flow.plaintextCredentialsExposed = true;
            flow.exposedCredentialsDetails = `POP3 USER/PASS credentials transmitted in cleartext ASCII on port ${flow.destPort} (RFC 8314 violation)`;
          }
        }
      }
      // Track Server Responses
      else {
        flow.serverResponses.push(line);

        // Server Banner Extraction
        if (!flow.serverBanner && (line.startsWith('220 ') || line.startsWith('* OK') || line.startsWith('+OK'))) {
          flow.serverBanner = line;
          const hostMatch = line.match(/(?:220[ -]|\* OK )([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
          if (hostMatch) {
            flow.serverHostname = hostMatch[1];
          }
        }

        // SMTP STARTTLS Advertisement
        if (upper.includes('250-STARTTLS') || upper.includes('250 STARTTLS')) {
          flow.startTlsAdvertised = true;
          flow.protocol = 'SMTP';
        } else if (upper.startsWith('220 2.0.0 READY TO START TLS') || upper.startsWith('220 READY')) {
          flow.startTlsNegotiated = true;
        }

        // IMAP STARTTLS Capability
        else if (upper.includes('CAPABILITY') && upper.includes('STARTTLS')) {
          flow.startTlsAdvertised = true;
          flow.protocol = 'IMAP';
        } else if (upper.includes('OK BEGIN TLS') || upper.includes('OK STARTTLS')) {
          flow.startTlsNegotiated = true;
        }

        // POP3 STLS Capability
        else if (upper.includes('+OK STLS') || upper.includes('STLS')) {
          flow.startTlsAdvertised = true;
          flow.protocol = 'POP3';
        } else if (upper.startsWith('+OK BEGIN TLS') || (flow.startTlsRequested && upper.startsWith('+OK'))) {
          flow.startTlsNegotiated = true;
        }
      }
    }
  }

  // If STARTTLS was requested and subsequent packets transitioned into TLS records, mark negotiated!
  if (flow.startTlsRequested && flow.hasTls) {
    flow.startTlsNegotiated = true;
  }
}
