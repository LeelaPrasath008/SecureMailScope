/**
 * SecureMailScope - AI Explanation Layer
 * STEP 8: Explain findings using Gemini AI
 * Evidence → Rule Engine → Findings → AI Explanation
 * The AI layer must NEVER create new findings.
 * SIH 2026 Problem Statement 26159
 */

import { GoogleGenAI } from '@google/genai';
import { CryptographicEvidence, Finding } from '../../types/security';

export interface AIExplanationResult {
  findingId: string;
  explanation: string;
  riskImpact: string;
  remediation: string;
  modelUsed?: string;
  isAiGenerated: boolean;
}

// Resilient Model Fallback Ladder per directive:
const MODEL_FALLBACK_LADDER = [
  'gemini-3.6-flash',
  'gemini-3.1-flash-lite',
  'gemini-flash-latest',
  'gemini-3.7-flash'
];

export async function explainFindingWithAI(
  finding: Finding,
  evidence: CryptographicEvidence[],
  apiKey?: string
): Promise<AIExplanationResult> {
  const effectiveKey = apiKey || (typeof process !== 'undefined' ? process.env?.GEMINI_API_KEY : undefined);

  // If no API key is available, generate deterministic grounded explanation
  if (!effectiveKey) {
    return generateDeterministicExplanation(finding, evidence);
  }

  const prompt = `You are SecureMailScope's AI Cryptographic Forensics Analyst for Email Security (SIH 2026 Problem Statement 26159).
You are evaluating a deterministic finding produced strictly by our rule engine from actual packet wire evidence.

CRITICAL INSTRUCTIONS:
1. You must explain ONLY the provided finding and evidence.
2. NEVER invent or hallucinate new findings, vulnerabilities, or packets.
3. Ground your explanation in RFC standards (RFC 8996, RFC 9325, RFC 8314, RFC 5280, NIST SP 800-52r2).

FINDING DETAILS:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Rule ID: ${finding.ruleId} (${finding.ruleTitle})
- Standard Reference: ${finding.standardReference}
- Evidence Statement: ${finding.evidenceStatement}
- Technical Reason: ${finding.technicalReason}

ACTUAL WIRE EVIDENCE FRAMES:
${evidence.map((e, idx) => `Evidence #${idx + 1} (${e.id}):
- Observation: ${e.rawObservation}
- Packet Frame Numbers: ${e.packetFrameNumbers.join(', ')}
- Byte Offset: ${e.byteOffsetHex || 'N/A'}
- Authoritative Standard: ${e.authoritativeStandard || 'RFC Standards'}`).join('\n\n')}

OUTPUT REQUIREMENT:
Respond with a JSON object in this exact format:
{
  "explanation": "concise, human-readable breakdown of the observed cryptographic evidence and why it failed policy",
  "riskImpact": "specific operational and security consequence of this vulnerability on email confidentiality/integrity",
  "remediation": "concrete, copyable server configuration steps (e.g. Postfix/Dovecot/Exchange directives) to remediate"
}`;

  try {
    const ai = new GoogleGenAI({ apiKey: effectiveKey });

    // Execute with automated model fallback ladder
    for (const model of MODEL_FALLBACK_LADDER) {
      try {
        const response = await ai.models.generateContent({
          model,
          contents: prompt,
          config: {
            responseMimeType: 'application/json'
          }
        });

        if (response.text) {
          const parsed = JSON.parse(response.text);
          return {
            findingId: finding.id,
            explanation: parsed.explanation || finding.technicalReason,
            riskImpact: parsed.riskImpact || finding.securityImpact,
            remediation: parsed.remediation || finding.recommendedAction,
            modelUsed: model,
            isAiGenerated: true
          };
        }
      } catch (err: any) {
        // Catch recoverable errors and attempt next model in fallback ladder
        console.warn(`Model ${model} unavailable or rate-limited (${err.message}). Attempting next fallback model...`);
        continue;
      }
    }
  } catch (err) {
    console.error('All Gemini fallback models exhausted or network error. Using grounded deterministic fallback.', err);
  }

  return generateDeterministicExplanation(finding, evidence);
}

function generateDeterministicExplanation(
  finding: Finding,
  evidence: CryptographicEvidence[]
): AIExplanationResult {
  const frames = evidence.flatMap((e) => e.packetFrameNumbers).join(', #');

  let explanation = finding.technicalReason;
  let riskImpact = finding.securityImpact;
  let remediation = finding.recommendedAction;

  if (finding.ruleId === 'RULE-TLS-001') {
    explanation = `Deterministic rule RULE-TLS-001 verified deprecated TLS in packet frame #${frames}. RFC 8996 prohibits TLS 1.0/1.1 across all transport links because it lacks modern AEAD authenticated encryption and is vulnerable to downgrade attacks.`;
    riskImpact = 'Man-in-the-middle attackers can force protocol downgrade and compromise email confidentiality during relay transmission.';
    remediation = 'In /etc/postfix/main.cf, set: smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1 and smtpd_tls_protocols = >=TLSv1.2.';
  } else if (finding.ruleId === 'RULE-CERT-001') {
    explanation = `The X.509 certificate presented during the TLS handshake has an expiration date that precedes the capture timestamp, directly violating RFC 5280 Section 4.1.2.5.`;
    riskImpact = 'Mail clients and MTAs will trigger security warning dialogs or refuse connection, causing delivery failures or conditioning users to click through warnings.';
    remediation = 'Renew certificate using Let\'s Encrypt certbot or install a fresh certificate issued by an approved Certificate Authority.';
  } else if (finding.ruleId === 'RULE-STARTTLS-002') {
    explanation = `The mail server advertised the STARTTLS extension in its EHLO response in Frame #${frames}, but the client proceeded to transmit commands without requesting encryption. This is characteristic of an active STARTTLS stripping attack or client misconfiguration.`;
    riskImpact = 'Email transmission occurs in cleartext, exposing message headers, body text, and sender/recipient identities to passive wiretaps.';
    remediation = 'Enforce mandatory TLS (e.g. port 587 submission with smtpd_tls_security_level = encrypt) or publish an MTA-STS policy (RFC 8461).';
  } else if (finding.ruleId === 'RULE-PLAIN-001') {
    explanation = `Mail authentication credentials were observed transmitted as plaintext ASCII across Frame #${frames}. Under RFC 8314 Section 3, cleartext authentication for email access is considered obsolete and unacceptable.`;
    riskImpact = 'Immediate account takeover. Anyone with access to the intermediate network or TAP interface can intercept and use the account password.';
    remediation = 'Immediately rotate the affected user password. Disable unencrypted POP3 port 110 and migrate to POP3S port 995 with required TLS 1.3.';
  } else if (finding.ruleId === 'RULE-IPV4-006') {
    explanation = `IPv4 datagram fragmentation was observed in Frame #${frames}. The More Fragments (MF) flag was asserted or the Fragment Offset was greater than zero.`;
    riskImpact = 'Fragmented packets can bypass certain stateful firewalls or indicate path MTU mismatches that cause latency.';
    remediation = 'Verify Path MTU Discovery (PMTUD) settings and ensure network MTU is standard (1500 bytes) without unnecessary fragmentation.';
  }

  return {
    findingId: finding.id,
    explanation,
    riskImpact,
    remediation,
    isAiGenerated: false
  };
}
