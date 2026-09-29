/**
 * SecureMailScope - Analyst Transparency Panel
 * SECTION 9: "Why This Conclusion Was Reached" auditor-friendly panel.
 * SIH 2026 Problem Statement 26159
 */

import React from 'react';
import { HelpCircle, CheckCircle2, AlertTriangle, ShieldAlert, FileText, Layers, Hash, Info } from 'lucide-react';
import { AnalystTransparencySummary, ConfidenceScores, ScopeValidationResult } from '../../types/security';

interface Props {
  transparency?: AnalystTransparencySummary;
  confidenceScores?: ConfidenceScores;
  scopeValidation?: ScopeValidationResult;
  pcapFilename?: string;
}

export const AnalystTransparencyPanel: React.FC<Props> = ({
  transparency,
  confidenceScores,
  scopeValidation,
  pcapFilename
}) => {
  const isOutOfScope = scopeValidation?.assessmentStatus === 'OUT OF SCOPE' || scopeValidation?.assessmentStatus === 'OUT_OF_SCOPE' || !scopeValidation?.isEmailInScope;
  const isInsufficient = scopeValidation?.assessmentStatus === 'INSUFFICIENT EVIDENCE' || scopeValidation?.assessmentStatus === 'INSUFFICIENT_EVIDENCE';

  const totalPackets = transparency?.totalPackets ?? 0;
  const smtpSessions = transparency?.smtpSessions ?? 0;
  const imapSessions = transparency?.imapSessions ?? 0;
  const pop3Sessions = transparency?.pop3Sessions ?? 0;
  const tlsSessions = transparency?.tlsSessions ?? 0;
  const detectedSummary = transparency?.detectedProtocolsSummary || 'None';
  const confidence = transparency?.confidenceScore || confidenceScores?.assessmentConfidence || 'HIGH';
  const reasonText = scopeValidation?.scopeReason || (isOutOfScope ? 'No email communication protocols detected.' : 'Email protocol traffic successfully reconstructed.');

  return (
    <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white tracking-tight uppercase">
            Analyst Transparency Panel: Why This Result Was Generated
          </h3>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">Auditor Confidence:</span>
          <span
            className={`px-2 py-0.5 rounded font-bold ${
              confidence === 'HIGH'
                ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                : confidence === 'MEDIUM'
                ? 'bg-amber-950/60 text-amber-300 border border-amber-800/60'
                : 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
            }`}
          >
            {confidence} CONFIDENCE
          </span>
        </div>
      </div>

      {/* Forensic Evidence Metric Cards per Requirement 8 */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 text-xs font-mono">
        <div className="p-3 bg-[#0A0E17] border border-slate-800 rounded-lg">
          <span className="text-[10px] text-slate-400 uppercase block">Packets Analysed</span>
          <span className="text-base sm:text-lg font-bold text-white tabular-nums">{totalPackets.toLocaleString()}</span>
        </div>

        <div className="p-3 bg-[#0A0E17] border border-slate-800 rounded-lg">
          <span className="text-[10px] text-slate-400 uppercase block">SMTP Sessions</span>
          <span className="text-base sm:text-lg font-bold text-cyan-300 tabular-nums">{smtpSessions}</span>
        </div>

        <div className="p-3 bg-[#0A0E17] border border-slate-800 rounded-lg">
          <span className="text-[10px] text-slate-400 uppercase block">IMAP Sessions</span>
          <span className="text-base sm:text-lg font-bold text-slate-200 tabular-nums">{imapSessions}</span>
        </div>

        <div className="p-3 bg-[#0A0E17] border border-slate-800 rounded-lg">
          <span className="text-[10px] text-slate-400 uppercase block">POP3 Sessions</span>
          <span className="text-base sm:text-lg font-bold text-slate-200 tabular-nums">{pop3Sessions}</span>
        </div>

        <div className="p-3 bg-[#0A0E17] border border-slate-800 rounded-lg">
          <span className="text-[10px] text-slate-400 uppercase block">TLS Sessions</span>
          <div className="flex items-center gap-1.5 mt-0.5">
            <span className="text-base sm:text-lg font-bold text-blue-400 tabular-nums">{tlsSessions}</span>
            {tlsSessions === 0 && (
              <span className="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-400">0 Observed</span>
            )}
          </div>
        </div>

        <div className="p-3 bg-[#0A0E17] border border-slate-800 rounded-lg">
          <span className="text-[10px] text-slate-400 uppercase block">Assessment</span>
          <span
            className={`text-xs font-bold block mt-1 ${
              isOutOfScope
                ? 'text-amber-400'
                : isInsufficient
                ? 'text-purple-400'
                : scopeValidation?.securityPosture === 'SECURE'
                ? 'text-emerald-400'
                : 'text-rose-400'
            }`}
          >
            {isOutOfScope
              ? 'OUT_OF_SCOPE'
              : isInsufficient
              ? 'INSUFFICIENT_EVIDENCE'
              : scopeValidation?.securityPosture || 'ASSESSED'}
          </span>
        </div>
      </div>

      {/* Primary Detected Protocol & Reason Banner */}
      <div className="p-3.5 bg-[#0A0E17] border border-slate-800/90 rounded-lg text-xs font-mono space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/70 pb-2">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 uppercase text-[10px]">Detected Protocol:</span>
            <span className="text-cyan-300 font-bold">{detectedSummary}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-slate-400 uppercase text-[10px]">Scope Rule:</span>
            <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
              isOutOfScope
                ? 'bg-amber-950/80 text-amber-300 border border-amber-800/70'
                : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/70'
            }`}>
              {isOutOfScope ? 'HALTED (OUT OF SCOPE)' : 'ACTIVE (IN SCOPE)'}
            </span>
          </div>
        </div>

        <div className="space-y-1">
          <span className="text-[10px] uppercase text-slate-400 font-semibold block">Reason:</span>
          <p className="text-slate-200 text-xs leading-relaxed font-sans">{reasonText}</p>
        </div>
      </div>

      {/* Rationale Bullet Points */}
      <div className="p-4 bg-[#0A0E17] border border-slate-800/90 rounded-lg space-y-2 text-xs">
        <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block font-semibold">
          Evidentiary Chain-of-Custody & Scope Rationale:
        </span>
        <ul className="space-y-1.5 text-slate-300">
          {(transparency?.whyConclusionReached || [
            `${totalPackets} packet frames analyzed passively from ${pcapFilename || 'capture'}.`,
            isOutOfScope
              ? 'Zero email sessions detected (SMTP: 0, IMAP: 0, POP3: 0).'
              : `${smtpSessions + imapSessions + pop3Sessions} email sessions reconstructed with complete frame linkage.`,
            `Observed TLS sessions: ${tlsSessions}.`,
            isOutOfScope
              ? 'Cryptographic email assessment halted to prevent false assurance. Security Posture classified as NOT ASSESSABLE / OUT_OF_SCOPE.'
              : 'Cryptographic posture evaluated strictly against RFC 8996, RFC 9325, and RFC 8314.',
            'Golden Forensic Rule enforced: NO EVIDENCE ≠ SECURE. NO EVIDENCE = NOT ASSESSABLE.'
          ]).map((point, idx) => (
            <li key={idx} className="flex items-start gap-2">
              <span className="text-cyan-400 font-mono select-none">›</span>
              <span className="leading-relaxed">{point}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Auditor Confidence Breakdown */}
      {confidenceScores && (
        <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Protocol Confidence:</span>
            <span className="text-cyan-300 font-bold">{confidenceScores.protocolConfidence}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Evidence Sufficiency:</span>
            <span className="text-emerald-300 font-bold">{confidenceScores.evidenceConfidence}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Assessment Confidence:</span>
            <span className="text-white font-bold">{confidenceScores.assessmentConfidence}</span>
          </div>
        </div>
      )}
    </div>
  );
};
