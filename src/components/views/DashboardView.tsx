import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Layers,
  Lock,
  FileSearch,
  CheckCircle2,
  FileCode2,
  Clock,
  Server,
  Zap,
  Sparkles,
  Sliders,
  ExternalLink,
  ChevronRight,
  HelpCircle,
  XCircle,
  Info,
  ShieldX
} from 'lucide-react';
import { DemoScenario, EmailSession, SecurityPosture } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { ForensicMetricGraphs } from '../common/ForensicMetricGraphs';
import { ProtocolAwareRouter } from '../common/ProtocolAwareRouter';
import { AnalystTransparencyPanel } from '../common/AnalystTransparencyPanel';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  scenario: DemoScenario;
  scenarios?: DemoScenario[];
  onSelectScenario?: (id: string) => void;
  posture: SecurityPosture;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectSession: (sessionId: string) => void;
  onSelectFinding: (findingId: string) => void;
}

export const DashboardView: React.FC<Props> = ({
  scenario,
  scenarios = [],
  onSelectScenario,
  posture,
  onNavigateTab,
  onSelectSession,
  onSelectFinding
}) => {
  const { summaryCounts, contributingFactors, categoryBreakdown } = posture;

  const isOutOfScope =
    posture.status === 'OUT OF SCOPE' ||
    posture.assessmentStatus === 'OUT OF SCOPE' ||
    scenario.assessmentStatus === 'OUT OF SCOPE' ||
    scenario.sessions.length === 0;

  const isInsufficient =
    posture.status === 'INSUFFICIENT EVIDENCE' ||
    posture.assessmentStatus === 'INSUFFICIENT EVIDENCE' ||
    scenario.assessmentStatus === 'INSUFFICIENT EVIDENCE';

  const isCritical = posture.status === 'CRITICAL RISK';
  const isHighRisk = posture.status === 'HIGH RISK';
  const isAtRisk = posture.status === 'AT RISK' || isCritical || isHighRisk;
  const isDegraded = posture.status === 'DEGRADED';
  const isSecure = posture.status === 'SECURE' && !isOutOfScope && !isInsufficient;

  const displayedStatus = isOutOfScope
    ? 'OUT OF SCOPE'
    : isInsufficient
    ? 'INSUFFICIENT EVIDENCE'
    : posture.status;

  const displayedRiskScore = isOutOfScope ? 'N/A' : isInsufficient ? 'INCOMPLETE' : isCritical ? '9.8 / 10' : isHighRisk ? '8.4 / 10' : isAtRisk ? '7.2 / 10' : isDegraded ? '5.0 / 10' : '0.0 / 10';

  return (
    <div className="p-4 sm:p-6 space-y-5 sm:space-y-6 max-w-7xl mx-auto">
      {/* Scenario Quick Selector Banner (1-Click Switcher) */}
      {scenarios.length > 0 && onSelectScenario && (
        <div className="bg-[#0F1623] border border-slate-800/90 rounded-xl p-3 px-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-slate-300">Quick Test Scenario:</span>
            <span className="text-xs text-slate-400 hidden sm:inline">Select a pre-analyzed traffic capture to inspect</span>
          </div>

          <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto pb-1 sm:pb-0">
            {scenarios.map((s) => {
              const isCurrent = s.id === scenario.id;
              const isScenOutOfScope = s.assessmentStatus === 'OUT OF SCOPE' || s.sessions.length === 0;
              return (
                <button
                  key={s.id}
                  onClick={() => onSelectScenario(s.id)}
                  className={`px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                    isCurrent
                      ? isScenOutOfScope
                        ? 'bg-amber-500/20 text-amber-200 border border-amber-500/50 shadow-xs font-semibold'
                        : 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/50 shadow-xs font-semibold'
                      : 'bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/60'
                  }`}
                >
                  <span className="sm:hidden">{s.title.split(':')[0]}</span>
                  <span className="hidden sm:inline">{s.title}</span>
                  {isScenOutOfScope && (
                    <span className="text-[9px] px-1 py-0.2 rounded bg-amber-950/80 border border-amber-700/60 text-amber-300 font-mono">
                      OUT OF SCOPE
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Hero Posture Banner - Guarded against false assurance */}
      <div className={`rounded-xl border p-4 sm:p-6 transition-all ${
        isOutOfScope
          ? 'bg-gradient-to-r from-amber-950/40 via-[#0F1623] to-[#0A0E17] border-amber-500/50 shadow-[0_0_20px_rgba(245,158,11,0.08)]'
          : isInsufficient
          ? 'bg-gradient-to-r from-purple-950/40 via-[#0F1623] to-[#0A0E17] border-purple-800/50'
          : isAtRisk
          ? 'bg-gradient-to-r from-rose-950/30 via-[#0F1623] to-[#0A0E17] border-rose-900/40'
          : isDegraded
          ? 'bg-gradient-to-r from-amber-950/30 via-[#0F1623] to-[#0A0E17] border-amber-900/40'
          : 'bg-gradient-to-r from-emerald-950/30 via-[#0F1623] to-[#0A0E17] border-emerald-900/40'
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-start gap-4">
            <div className={`p-3.5 rounded-xl border shrink-0 ${
              isOutOfScope
                ? 'bg-amber-950/60 border-amber-700/80 text-amber-400'
                : isInsufficient
                ? 'bg-purple-950/60 border-purple-800/80 text-purple-400'
                : isAtRisk
                ? 'bg-rose-950/60 border-rose-800/80 text-rose-400'
                : isDegraded
                ? 'bg-amber-950/60 border-amber-800/80 text-amber-400'
                : 'bg-emerald-950/60 border-emerald-800/80 text-emerald-400'
            }`}>
              {isOutOfScope ? (
                <HelpCircle className="w-8 h-8" />
              ) : isInsufficient ? (
                <Clock className="w-8 h-8" />
              ) : isAtRisk ? (
                <ShieldAlert className="w-8 h-8" />
              ) : (
                <ShieldCheck className="w-8 h-8" />
              )}
            </div>

            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                  Cryptographic Posture Assessment
                </span>
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded-md border ${
                  isOutOfScope
                    ? 'text-amber-300 bg-amber-950/70 border-amber-700/70'
                    : isInsufficient
                    ? 'text-purple-300 bg-purple-950/70 border-purple-800/60'
                    : isAtRisk
                    ? 'text-rose-300 bg-rose-950/70 border-rose-800/60'
                    : isDegraded
                    ? 'text-amber-300 bg-amber-950/70 border-amber-800/60'
                    : 'text-emerald-300 bg-emerald-950/70 border-emerald-800/60'
                }`}>
                  {displayedStatus}
                </span>
                {isOutOfScope && (
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700">
                    POSTURE: NOT ASSESSABLE
                  </span>
                )}
                <span className="text-xs font-mono text-slate-400">
                  Risk Score: <strong className="text-white">{displayedRiskScore}</strong>
                </span>
              </div>

              <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                {scenario.title}
              </h2>
              <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
                {scenario.description}
              </p>

              {/* Anti-False-Assurance Banner */}
              {isOutOfScope && (
                <div className="mt-3 p-2.5 bg-[#0A0E17]/90 border border-amber-800/60 rounded-lg flex items-start gap-2 text-xs">
                  <ShieldX className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div className="text-amber-200">
                    <span className="font-bold">EVIDENTIARY SCOPE RULE:</span>{' '}
                    <span>
                      Cryptographic email evaluation halted. Reason:{' '}
                      <strong className="text-white">
                        {scenario.scopeValidation?.scopeReason || posture.scopeReason || 'No SMTP, IMAP, POP3, SMTPS, IMAPS, or POP3S traffic identified.'}
                      </strong>{' '}
                      SecureMailScope never outputs &quot;SECURE&quot; or &quot;0 Findings&quot; when no email traffic was analyzed.
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="flex flex-wrap sm:flex-nowrap items-center gap-2.5 shrink-0">
            <button
              onClick={() => onNavigateTab('findings')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-2 transition-colors cursor-pointer"
            >
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>Review {scenario.findings.length} Findings</span>
            </button>

            <button
              onClick={() => onNavigateTab('posture')}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center gap-2 shadow-xs transition-colors cursor-pointer"
            >
              <Sliders className="w-4 h-4" />
              <span>What-If Simulator</span>
            </button>
          </div>
        </div>

        {/* Contributing Factors inline alert */}
        {contributingFactors.length > 0 && (
          <div className="mt-5 pt-4 border-t border-slate-800/70">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
              Primary Identified Security Violations
            </span>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {contributingFactors.map((factor, idx) => (
                <div
                  key={idx}
                  onClick={() => onNavigateTab('findings')}
                  className="bg-[#0A0E17]/80 hover:bg-[#0E1523] border border-slate-800 rounded-lg p-2.5 flex items-start justify-between gap-2 cursor-pointer transition-colors"
                >
                  <div className="min-w-0">
                    <span className="text-xs font-semibold text-slate-200 block truncate">
                      {factor.label}
                    </span>
                    <span className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                      {factor.description}
                    </span>
                  </div>
                  <SeverityBadge severity={factor.severity} size="sm" />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* SIH INNOVATION: Protocol-Aware Assessment Routing (Section 10) */}
      <ProtocolAwareRouter
        classification={scenario.pcapMetadata.protocolClassification}
        scopeValidation={scenario.scopeValidation || posture.scopeValidation}
        onExploreRoute={(type) => {
          if (type.includes('Email')) {
            onNavigateTab('sessions');
          } else {
            onNavigateTab('pcap_analysis');
          }
        }}
      />

      {/* FORENSIC TRANSPARENCY: Why This Conclusion Was Reached (Section 9) */}
      <AnalystTransparencyPanel
        transparency={scenario.analystTransparency || posture.transparencySummary}
        confidenceScores={scenario.confidenceScores || posture.confidenceScores}
        scopeValidation={scenario.scopeValidation || posture.scopeValidation}
        pcapFilename={scenario.pcapMetadata.filename}
      />

      {/* Forensic Overview Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-3.5 space-y-1">
          <span className="text-xs text-slate-400 font-medium block">Total Streams</span>
          <div className="text-2xl font-bold font-mono text-white tabular-nums">
            {summaryCounts.totalSessions}
          </div>
          <span className="text-[11px] text-slate-400 block">
            {isOutOfScope ? '0 Reconstructed' : 'Reconstructed'}
          </span>
        </div>

        <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-3.5 space-y-1">
          <span className="text-xs text-slate-400 font-medium block">SMTP Flows</span>
          <div className="text-2xl font-bold font-mono text-cyan-300 tabular-nums">
            {summaryCounts.smtpSessions}
          </div>
          <span className="text-[11px] text-slate-400 block">Ports 25, 587, 465</span>
        </div>

        <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-3.5 space-y-1">
          <span className="text-xs text-slate-400 font-medium block">IMAP / POP3</span>
          <div className="text-2xl font-bold font-mono text-slate-200 tabular-nums">
            {summaryCounts.imapSessions + summaryCounts.pop3Sessions}
          </div>
          <span className="text-[11px] text-slate-400 block">Mailbox Access</span>
        </div>

        <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-3.5 space-y-1">
          <span className="text-xs text-slate-400 font-medium block">TLS Handshakes</span>
          <div className="text-2xl font-bold font-mono text-blue-400 tabular-nums">
            {summaryCounts.tlsSessions}
          </div>
          <span className="text-[11px] text-slate-400 block">
            {isOutOfScope ? '0 (Halted)' : 'Negotiated Sessions'}
          </span>
        </div>

        <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-3.5 space-y-1">
          <span className="text-xs text-slate-400 font-medium block">Risk Status</span>
          <div className={`text-2xl font-bold font-mono tabular-nums ${
            isOutOfScope
              ? 'text-amber-400 text-lg sm:text-xl'
              : summaryCounts.criticalFindings > 0
              ? 'text-rose-400'
              : 'text-slate-300'
          }`}>
            {isOutOfScope ? 'N/A' : summaryCounts.criticalFindings}
          </div>
          <span className="text-[11px] text-slate-400 block">
            {isOutOfScope ? 'Out of Scope' : 'Critical Action'}
          </span>
        </div>

        <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-3.5 space-y-1">
          <span className="text-xs text-slate-400 font-medium block">Total Findings</span>
          <div className="text-2xl font-bold font-mono text-amber-300 tabular-nums">
            {summaryCounts.totalFindings}
          </div>
          <span className="text-[11px] text-slate-400 block">RFC / Policy Rules</span>
        </div>
      </div>

      {/* 3 Core Forensic Telemetry Graphs */}
      <ForensicMetricGraphs scenario={scenario} />

      {/* Cryptographic Posture 4-Pillar Breakdown */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-white tracking-tight">
              Cryptographic Assessment Pillars
            </h3>
            <p className="text-xs text-slate-400">
              Deterministic evaluation across transport layers, cipher suites, X.509 certificates, and protocol conformance.
            </p>
          </div>

          <button
            onClick={() => onNavigateTab('posture')}
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer transition-colors"
          >
            <span>Explore Posture & Standards</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {/* Pillar 1: Transport Security */}
          <div
            onClick={() => onNavigateTab('posture')}
            className="bg-[#0F1623] hover:bg-[#151F32] border border-slate-800 rounded-xl p-4 cursor-pointer transition-all space-y-3 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">Transport Security</span>
              <SeverityBadge severity={categoryBreakdown.transportSecurity.severity} size="sm" />
            </div>
            <div>
              <div className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                {categoryBreakdown.transportSecurity.status}
              </div>
              <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">
                {categoryBreakdown.transportSecurity.keyMetric}
              </p>
            </div>
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
              <span className="font-mono tabular-nums">{categoryBreakdown.transportSecurity.evidenceCount} evidence frames</span>
              <span className="text-cyan-400 group-hover:underline">Inspect →</span>
            </div>
          </div>

          {/* Pillar 2: Cryptography & Ciphers */}
          <div
            onClick={() => onNavigateTab('posture')}
            className="bg-[#0F1623] hover:bg-[#151F32] border border-slate-800 rounded-xl p-4 cursor-pointer transition-all space-y-3 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">Cryptography & Ciphers</span>
              <SeverityBadge severity={categoryBreakdown.cryptography.severity} size="sm" />
            </div>
            <div>
              <div className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                {categoryBreakdown.cryptography.status}
              </div>
              <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">
                {categoryBreakdown.cryptography.keyMetric}
              </p>
            </div>
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
              <span className="font-mono tabular-nums">{categoryBreakdown.cryptography.evidenceCount} evidence frames</span>
              <span className="text-cyan-400 group-hover:underline">Inspect →</span>
            </div>
          </div>

          {/* Pillar 3: Certificate Security */}
          <div
            onClick={() => onNavigateTab('posture')}
            className="bg-[#0F1623] hover:bg-[#151F32] border border-slate-800 rounded-xl p-4 cursor-pointer transition-all space-y-3 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">Certificate Security</span>
              <SeverityBadge severity={categoryBreakdown.certificateSecurity.severity} size="sm" />
            </div>
            <div>
              <div className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                {categoryBreakdown.certificateSecurity.status}
              </div>
              <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">
                {categoryBreakdown.certificateSecurity.keyMetric}
              </p>
            </div>
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
              <span className="font-mono tabular-nums">{categoryBreakdown.certificateSecurity.evidenceCount} evidence frames</span>
              <span className="text-cyan-400 group-hover:underline">Inspect →</span>
            </div>
          </div>

          {/* Pillar 4: Protocol Security */}
          <div
            onClick={() => onNavigateTab('posture')}
            className="bg-[#0F1623] hover:bg-[#151F32] border border-slate-800 rounded-xl p-4 cursor-pointer transition-all space-y-3 group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">Protocol Security</span>
              <SeverityBadge severity={categoryBreakdown.protocolSecurity.severity} size="sm" />
            </div>
            <div>
              <div className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                {categoryBreakdown.protocolSecurity.status}
              </div>
              <p className="text-xs text-slate-400 mt-0.5 line-clamp-2">
                {categoryBreakdown.protocolSecurity.keyMetric}
              </p>
            </div>
            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
              <span className="font-mono tabular-nums">{categoryBreakdown.protocolSecurity.evidenceCount} evidence frames</span>
              <span className="text-cyan-400 group-hover:underline">Inspect →</span>
            </div>
          </div>
        </div>
      </div>

      {/* Reconstructed Sessions Triage Table / Scope Callout */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Observed Email Traffic Streams</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {isOutOfScope
                ? 'Handshake & state machine dissection halted per scope validation rule'
                : 'Select any session to open full handshake dissection, certificate details, and packet frames'}
            </p>
          </div>

          {scenario.sessions.length > 0 && (
            <button
              onClick={() => onNavigateTab('sessions')}
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer transition-colors"
            >
              <span>View All {scenario.sessions.length} Sessions</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {scenario.sessions.length === 0 ? (
          <div className="p-6 bg-[#0A0E17] border border-slate-800 rounded-xl text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto text-amber-400">
              <HelpCircle className="w-6 h-6" />
            </div>
            <div className="max-w-md mx-auto space-y-1">
              <h4 className="text-sm font-bold text-white">0 Email Sessions Identified</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Scope Validation Layer identified{' '}
                <span className="text-amber-300 font-mono font-semibold">
                  {scenario.pcapMetadata.protocolClassification?.primaryProtocol || 'non-email'}
                </span>{' '}
                traffic. Handshake reconstruction was not invoked to prevent false assurance.
              </p>
            </div>
            <div className="pt-2 flex flex-wrap items-center justify-center gap-2">
              <button
                onClick={() => onSelectScenario && onSelectScenario('scenario-secure-smtp')}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium cursor-pointer"
              >
                Inspect Scenario 1 (TLS 1.3 SMTP)
              </button>
              <button
                onClick={() => onSelectScenario && onSelectScenario('scenario-legacy-smtp')}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium cursor-pointer"
              >
                Inspect Scenario 2 (TLS 1.0 Downgrade)
              </button>
              <button
                onClick={() => onNavigateTab('pcap_analysis')}
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium cursor-pointer"
              >
                Upload Email PCAP
              </button>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-800/80">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="bg-[#0A0E17] border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="py-2.5 px-3.5 font-semibold">Session ID</th>
                  <th className="py-2.5 px-3 font-semibold">Protocol</th>
                  <th className="py-2.5 px-3 font-semibold">Endpoints</th>
                  <th className="py-2.5 px-3 font-semibold">STARTTLS</th>
                  <th className="py-2.5 px-3 font-semibold">TLS Version</th>
                  <th className="py-2.5 px-3 font-semibold">Cipher Suite</th>
                  <th className="py-2.5 px-3 font-semibold">Risk</th>
                  <th className="py-2.5 px-3.5 text-right font-semibold">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-[#0F1623]">
                {scenario.sessions.map((session) => (
                  <tr
                    key={session.id}
                    onClick={() => onSelectSession(session.id)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    <td className="py-3 px-3.5 text-cyan-300 font-bold">{session.id}</td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded-md bg-slate-800 text-slate-200 text-[10px] font-semibold">
                        {session.protocol}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      <div className="tabular-nums">
                        {session.sourceIp}:{session.sourcePort}
                      </div>
                      <div className="text-[10px] text-slate-400 tabular-nums">
                        → {session.destIp}:{session.destPort}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      {session.startTlsNegotiated ? (
                        <span className="text-emerald-400 font-semibold">Completed</span>
                      ) : session.startTlsAdvertised ? (
                        <span className="text-amber-400 font-medium">Advertised Only</span>
                      ) : (
                        <span className="text-slate-400">None (Plaintext)</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      {session.tlsHandshake ? (
                        <span
                          className={
                            session.tlsHandshake.isDeprecatedVersion
                              ? 'text-rose-400 font-bold'
                              : 'text-slate-200 font-medium'
                          }
                        >
                          {session.tlsHandshake.negotiatedVersion}
                        </span>
                      ) : (
                        <span className="text-slate-400">None</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-300 max-w-[200px] truncate" title={session.tlsHandshake?.cipherSuite.ianaName || 'None'}>
                      {session.tlsHandshake ? (
                        <span className={session.tlsHandshake.cipherSuite.isWeak ? 'text-amber-300 font-medium' : 'text-slate-300'}>
                          {session.tlsHandshake.cipherSuite.ianaName}
                        </span>
                      ) : (
                        <span className="text-slate-400">None</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <SeverityBadge severity={session.risk} size="sm" />
                    </td>
                    <td className="py-3 px-3.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectSession(session.id);
                        }}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-cyan-600 hover:text-white text-cyan-300 border border-slate-700 hover:border-cyan-500 rounded-md text-[11px] font-sans font-medium transition-all cursor-pointer"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
