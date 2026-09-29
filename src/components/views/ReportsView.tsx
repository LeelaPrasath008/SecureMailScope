import React, { useState } from 'react';
import {
  FileText,
  Download,
  Printer,
  Copy,
  Check,
  Hash,
  Shield,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Layers,
  Terminal
} from 'lucide-react';
import { DemoScenario, SecurityPosture } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { ConfidenceBadge } from '../common/ConfidenceBadge';

interface Props {
  scenario: DemoScenario;
  posture: SecurityPosture;
}

export const ReportsView: React.FC<Props> = ({ scenario, posture }) => {
  const [activeTab, setActiveTab] = useState<'preview' | 'json' | 'html'>('preview');
  const [copied, setCopied] = useState(false);

  const meta = scenario.pcapMetadata;
  const sessions = scenario.sessions;
  const findings = scenario.findings;
  const evidence = scenario.evidenceList;

  // JSON Report Generator
  const generateJsonReport = () => {
    return JSON.stringify(
      {
        report_meta: {
          product: 'SecureMailScope',
          version: '2026.1-SIH',
          problem_statement: 'SIH 2026 PS 26159',
          generated_timestamp: new Date().toISOString(),
          evaluation_mode: 'DEMONSTRATION'
        },
        evidence_custody: {
          evidence_id: meta.id,
          filename: meta.filename,
          sha256: meta.sha256,
          file_size_bytes: meta.fileSizeBytes,
          capture_timestamp: meta.captureTimestamp,
          analysis_timestamp: meta.analysisTimestamp,
          interface: meta.capturedInterface,
          evidence_confidence: meta.confidence
        },
        protocol_classification: scenario.pcapMetadata.protocolClassification || null,
        scope_validation: scenario.scopeValidation || posture.scopeValidation || null,
        analyst_transparency: scenario.analystTransparency || posture.transparencySummary || null,
        confidence_scores: scenario.confidenceScores || posture.confidenceScores || null,
        executive_posture: {
          overall_status: posture.status,
          is_email_in_scope: posture.isEmailInScope,
          assessment_status: posture.assessmentStatus,
          scope_reason: posture.scopeReason,
          summary_counts: posture.summaryCounts,
          contributing_factors: posture.contributingFactors,
          category_breakdown: posture.categoryBreakdown
        },
        reconstructed_sessions: sessions.map(s => ({
          session_id: s.id,
          protocol: s.protocol,
          client: `${s.sourceIp}:${s.sourcePort}`,
          server: `${s.destIp}:${s.destPort} (${s.serverHostname || 'unknown'})`,
          starttls_negotiated: s.startTlsNegotiated,
          tls_handshake: s.tlsHandshake
            ? {
                version: s.tlsHandshake.negotiatedVersion,
                is_deprecated: s.tlsHandshake.isDeprecatedVersion,
                cipher_suite: s.tlsHandshake.cipherSuite.ianaName,
                forward_secrecy: s.tlsHandshake.forwardSecrecy,
                certificate: s.tlsHandshake.certificate
                  ? {
                      subject: s.tlsHandshake.certificate.subject,
                      issuer: s.tlsHandshake.certificate.issuer,
                      valid_until: s.tlsHandshake.certificate.validUntil,
                      is_expired: s.tlsHandshake.certificate.isExpired,
                      chain_status: s.tlsHandshake.certificate.chainStatus
                    }
                  : null
              }
            : null,
          risk: s.risk,
          confidence: s.evidenceConfidence
        })),
        findings: findings.map(f => ({
          finding_id: f.id,
          title: f.title,
          severity: f.severity,
          confidence: f.confidence,
          affected_session: f.affectedSessionId,
          rule: f.ruleTitle,
          standard_reference: f.standardReference,
          evidence_statement: f.evidenceStatement,
          technical_reason: f.technicalReason,
          impact: f.securityImpact,
          recommended_action: f.recommendedAction,
          priority_order: f.priorityOrder
        })),
        raw_evidence_frames: evidence.map(e => ({
          evidence_id: e.id,
          session_id: e.sessionId,
          type: e.evidenceType,
          packet_frames: e.packetFrameNumbers,
          byte_offset: e.byteOffsetHex,
          observation: e.rawObservation,
          confidence: e.confidence,
          standard: e.authoritativeStandard
        })),
        forensic_limitations:
          'Assessment reflects passive observations in the provided packet capture. Incomplete captures or dropped frames may limit visibility.'
      },
      null,
      2
    );
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(generateJsonReport());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(generateJsonReport());
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `SecureMailScope_${meta.id}_AuditReport.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleDownloadHtml = () => {
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>SecureMailScope Cryptographic Audit Report - ${meta.id}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #090D14; color: #F1F5F9; padding: 40px; }
    h1, h2, h3 { font-family: monospace; color: #38BDF8; }
    .box { background: #0B111A; border: 1px solid #1E293B; padding: 20px; border-radius: 6px; margin-bottom: 20px; }
    .hash { font-family: monospace; background: #05080E; padding: 8px; border: 1px solid #334155; word-break: break-all; }
    .risk-at-risk { color: #F87171; font-weight: bold; }
    .risk-secure { color: #34D399; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; font-family: monospace; font-size: 12px; margin-top: 10px; }
    th, td { border: 1px solid #334155; padding: 8px; text-align: left; }
    th { background: #1E293B; }
  </style>
</head>
<body>
  <h1>SECUREMAILSCOPE AUDIT REPORT</h1>
  <p>Cryptographic Security Posture Assessment for Secure Email Communications</p>
  <div class="box">
    <h2>1. Executive Summary</h2>
    <p>Overall Security Posture: <span class="${posture.status === 'AT RISK' ? 'risk-at-risk' : 'risk-secure'}">${posture.status}</span></p>
    <p>Analyzed PCAP: ${meta.filename}</p>
    <p>SHA-256 Integrity: <span class="hash">${meta.sha256}</span></p>
  </div>
  <div class="box">
    <h2>2. Findings Summary</h2>
    <table>
      <tr><th>ID</th><th>Severity</th><th>Session</th><th>Title</th><th>Standard Reference</th></tr>
      ${findings.map(f => `<tr><td>${f.id}</td><td>${f.severity}</td><td>${f.affectedSessionId}</td><td>${f.title}</td><td>${f.standardReference}</td></tr>`).join('')}
    </table>
  </div>
  <div class="box">
    <h2>3. Regulatory & Authoritative RFC Standards Baseline</h2>
    <ul>
      <li><strong>BCP 195 (RFC 8996 & RFC 9325):</strong> Deprecating TLS 1.0/1.1; Mandates TLS 1.2+ with AEAD and Forward Secrecy.</li>
      <li><strong>RFC 8314:</strong> Cleartext Considered Obsolete for Email Submission and Access.</li>
      <li><strong>RFC 8461:</strong> SMTP MTA Strict Transport Security (MTA-STS).</li>
      <li><strong>RFC 5280:</strong> Internet X.509 PKI Certificate and CRL Profile.</li>
      <li><strong>CVE-2016-2183:</strong> Sweet32 64-bit Block Cipher Birthday Attack Prohibition.</li>
    </ul>
  </div>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SecureMailScope_${meta.id}_AuditReport.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Cryptographic Security Posture Audit Report</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Verifiable compliance and cryptographic posture documentation with cryptographic evidence hashes.
          </p>
        </div>

        {/* Action Buttons (Section 20) */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadJson}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-mono font-medium transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Download JSON</span>
          </button>

          <button
            onClick={handleDownloadHtml}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-mono font-medium transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            <span>Download HTML</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-mono font-semibold transition-colors cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </div>

      {/* Format Selector Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('preview')}
          className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
            activeTab === 'preview'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          Audit Document Preview
        </button>
        <button
          onClick={() => setActiveTab('json')}
          className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
            activeTab === 'json'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          Raw JSON Payload
        </button>
      </div>

      {/* Main Report Document Structure (Section 20) */}
      {activeTab === 'preview' ? (
        <div className="bg-[#0B0F17] border border-slate-800 rounded p-8 space-y-8 font-sans print:bg-white print:text-black print:p-0 print:border-none">
          {/* Document Header */}
          <div className="border-b border-slate-800/80 pb-6">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider block font-bold">
                  CONFIDENTIAL SECURITY POSTURE AUDIT
                </span>
                <h1 className="text-2xl font-bold text-white tracking-tight mt-1">
                  SECUREMAILSCOPE POSTURE ASSESSMENT
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  SIH 2026 Problem Statement 26159 · AI-Assisted Cryptographic Forensic Assessment
                </p>
              </div>
              <div className="text-right font-mono text-xs text-slate-400">
                <div>Generated: {new Date().toUTCString()}</div>
                <div>Status: <span className="text-emerald-400 font-bold">VERIFIED FORENSIC RECORD</span></div>
              </div>
            </div>
          </div>

          {/* 1. Executive Summary */}
          <div className="space-y-3">
            <h2 className="text-base font-bold text-white font-mono flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-cyan-400">1.</span> Executive Summary
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-3.5 bg-[#080C14] border border-slate-800 rounded">
                <span className="text-slate-500 block text-[10px] uppercase">Assessed Posture</span>
                <span
                  className={`text-lg font-bold block mt-1 ${
                    posture.status === 'AT RISK'
                      ? 'text-rose-400'
                      : posture.status === 'DEGRADED'
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {posture.status}
                </span>
              </div>
              <div className="p-3.5 bg-[#080C14] border border-slate-800 rounded">
                <span className="text-slate-500 block text-[10px] uppercase">Total Findings</span>
                <span className="text-lg font-bold text-slate-200 block mt-1 tabular-nums">
                  {findings.length} Findings ({posture.summaryCounts.criticalFindings} Critical, {posture.summaryCounts.highFindings} High)
                </span>
              </div>
              <div className="p-3.5 bg-[#080C14] border border-slate-800 rounded">
                <span className="text-slate-500 block text-[10px] uppercase">Reconstructed Sessions</span>
                <span className="text-lg font-bold text-cyan-400 block mt-1 tabular-nums">
                  {sessions.length} Mail Streams
                </span>
              </div>
            </div>
          </div>

          {/* 2. Evidence Metadata & Custody (SHA-256 MANDATORY) */}
          <div className="space-y-3">
            <h2 className="text-base font-bold text-white font-mono flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-cyan-400">2.</span> Evidence Metadata & Digital Custody
            </h2>
            <div className="p-4 bg-[#080C14] border border-slate-800 rounded text-xs font-mono space-y-2.5">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Evidence ID</span>
                  <span className="text-slate-200 font-bold">{meta.id}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Filename</span>
                  <span className="text-slate-200">{meta.filename}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">File Size</span>
                  <span className="text-slate-200">{(meta.fileSizeBytes / 1024).toFixed(1)} KB</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Packets Processed</span>
                  <span className="text-slate-200 tabular-nums">{meta.packetCount.toLocaleString()}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-500 text-[10px] uppercase block flex items-center gap-1">
                  <Hash className="w-3 h-3 text-cyan-400" />
                  Evidence Cryptographic SHA-256 Digest (Verifiable Integrity)
                </span>
                <span className="text-cyan-300 bg-[#05080E] p-2 rounded border border-slate-800 block text-xs break-all select-all mt-1">
                  {meta.sha256}
                </span>
              </div>
            </div>
          </div>

          {/* 3. Findings & Evidence Details */}
          <div className="space-y-3">
            <h2 className="text-base font-bold text-white font-mono flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-cyan-400">3.</span> Cryptographic Findings & Rules Citation
            </h2>
            <div className="space-y-3">
              {findings.map(f => (
                <div key={f.id} className="p-4 bg-[#080C14] border border-slate-800 rounded space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between border-b border-slate-800/60 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400 font-bold">{f.id}</span>
                      <span className="font-sans font-bold text-white text-sm">{f.title}</span>
                    </div>
                    <SeverityBadge severity={f.severity} />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                    <div>
                      <span className="text-slate-500 uppercase text-[10px] block">Observed Evidence</span>
                      <p className="text-slate-300 font-sans mt-0.5">{f.evidenceStatement}</p>
                    </div>
                    <div>
                      <span className="text-slate-500 uppercase text-[10px] block">Standard Reference</span>
                      <p className="text-cyan-300 mt-0.5 font-bold">{f.standardReference}</p>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800/60">
                    <span className="text-emerald-400 uppercase text-[10px] block">
                      Recommended Remediation (Priority #{f.priorityOrder}):
                    </span>
                    <p className="text-slate-200 mt-0.5">{f.recommendedAction}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Standards & RFC Baseline */}
          <div className="space-y-3">
            <h2 className="text-base font-bold text-white font-mono flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-cyan-400">4.</span> Regulatory & Authoritative RFC Baseline
            </h2>
            <div className="p-4 bg-[#080C14] border border-slate-800 rounded text-xs font-mono space-y-2">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                <div className="p-2 bg-[#05080E] rounded border border-slate-800/80">
                  <span className="text-cyan-400 font-bold block">BCP 195 (RFC 8996 & RFC 9325)</span>
                  <span className="text-slate-400 text-[10px]">Deprecates TLS 1.0/1.1; Mandates TLS 1.2+ with AEAD and Ephemeral PFS</span>
                </div>
                <div className="p-2 bg-[#05080E] rounded border border-slate-800/80">
                  <span className="text-cyan-400 font-bold block">RFC 8314</span>
                  <span className="text-slate-400 text-[10px]">Cleartext Considered Obsolete for Email Submission and Access</span>
                </div>
                <div className="p-2 bg-[#05080E] rounded border border-slate-800/80">
                  <span className="text-cyan-400 font-bold block">RFC 8461 (MTA-STS) & RFC 7672 (DANE)</span>
                  <span className="text-slate-400 text-[10px]">Mandatory TLS delivery policies and DNSSEC peer validation against STRIPTLS</span>
                </div>
                <div className="p-2 bg-[#05080E] rounded border border-slate-800/80">
                  <span className="text-cyan-400 font-bold block">RFC 5280 & CAB Forum Baseline</span>
                  <span className="text-slate-400 text-[10px]">X.509 validity windows, SAN domain binding, and SHA-256+ signatures</span>
                </div>
              </div>
            </div>
          </div>

          {/* 5. Confidence & Limitations (Section 20) */}
          <div className="space-y-3">
            <h2 className="text-base font-bold text-white font-mono flex items-center gap-2 border-b border-slate-800 pb-2">
              <span className="text-cyan-400">5.</span> Forensic Confidence, Scope & Limitations
            </h2>
            <div className="p-4 bg-[#080C14] border border-slate-800 rounded text-xs text-slate-300 space-y-2 leading-relaxed">
              <p>
                <strong>Methodology:</strong> This assessment was performed passively through packet capture dissection, protocol grammar parsing, and deterministic rule evaluation. Zero active traffic injection or live mail interception was conducted.
              </p>
              <p>
                <strong>Limitations:</strong> Cryptographic determinations reflect the specific TCP sessions captured in evidence {meta.id}. MTAs employing adaptive or opportunistic TLS policies with unobserved peer hosts may exhibit different cryptographic profiles in uncaptured sessions.
              </p>
            </div>
          </div>
        </div>
      ) : (
        /* Raw JSON Output View */
        <div className="bg-[#0B0F17] border border-slate-800 rounded p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">
              Machine-Readable Forensic JSON Export
            </span>
            <button
              onClick={handleCopyJson}
              className="flex items-center gap-1.5 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
            </button>
          </div>
          <pre className="p-4 bg-[#05080E] border border-slate-800 rounded text-xs font-mono text-cyan-300 overflow-x-auto whitespace-pre max-h-[600px] leading-relaxed select-all">
            {generateJsonReport()}
          </pre>
        </div>
      )}
    </div>
  );
};
