import React, { useState } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  ArrowRight,
  ShieldAlert,
  FileCode2,
  Cpu,
  Layers,
  CheckCircle2,
  ExternalLink,
  BookOpen,
  Zap,
  Copy,
  Check,
  Code
} from 'lucide-react';
import { Finding, SeverityLevel } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  findings: Finding[];
  selectedFindingId: string | null;
  onSelectFinding: (findingId: string) => void;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectSession: (sessionId: string) => void;
}

export const FindingsView: React.FC<Props> = ({
  findings,
  selectedFindingId,
  onSelectFinding,
  onNavigateTab,
  onSelectSession
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [confidenceFilter, setConfidenceFilter] = useState<'COMPLETE' | 'PARTIAL' | 'INSUFFICIENT' | 'ALL'>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const countBySeverity = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length
  };

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (confidenceFilter !== 'ALL' && f.confidence !== confidenceFilter) return false;
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      const matchId = f.id.toLowerCase().includes(q);
      const matchTitle = f.title.toLowerCase().includes(q);
      const matchSession = f.affectedSessionId.toLowerCase().includes(q);
      const matchRule = f.ruleTitle.toLowerCase().includes(q) || f.standardReference.toLowerCase().includes(q);
      const matchEv = f.evidenceStatement.toLowerCase().includes(q);
      if (!matchId && !matchTitle && !matchSession && !matchRule && !matchEv) return false;
    }
    return true;
  });

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  // Helper to extract a clean configuration snippet based on rule/action
  const getRemediationSnippet = (finding: Finding) => {
    if (finding.ruleId.includes('TLS') || finding.title.toLowerCase().includes('tls 1.0')) {
      return `# /etc/postfix/main.cf
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_protocols = >=TLSv1.2
smtp_tls_protocols = >=TLSv1.2
tls_high_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256`;
    }
    if (finding.title.toLowerCase().includes('cipher') || finding.title.toLowerCase().includes('sweet32') || finding.title.toLowerCase().includes('3des')) {
      return `# /etc/postfix/main.cf
smtpd_tls_mandatory_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, 3DES, RC4, MD5, PSK, SRP, DSS
tls_preempt_cipherlist = yes`;
    }
    if (finding.title.toLowerCase().includes('plain') || finding.title.toLowerCase().includes('cleartext')) {
      return `# /etc/dovecot/conf.d/10-auth.conf
disable_plaintext_auth = yes
auth_mechanisms = plain login
ssl = required`;
    }
    return finding.recommendedAction;
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header and Summary Counters */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <span>Security Findings & Remediation</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Grounded cryptographic violations linked directly to packet wire evidence, RFC standards, and copyable server configuration fixes.
          </p>
        </div>

        {/* Severity Count Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setSeverityFilter('ALL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              severityFilter === 'ALL'
                ? 'bg-slate-700 text-white font-semibold'
                : 'bg-slate-800/80 text-slate-400 hover:text-white'
            }`}
          >
            All ({findings.length})
          </button>
          <button
            onClick={() => setSeverityFilter('CRITICAL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              severityFilter === 'CRITICAL'
                ? 'bg-rose-900/60 text-rose-200 border border-rose-700 font-semibold'
                : 'bg-slate-800/80 text-rose-400 hover:bg-slate-800'
            }`}
          >
            Critical ({countBySeverity.CRITICAL})
          </button>
          <button
            onClick={() => setSeverityFilter('HIGH')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              severityFilter === 'HIGH'
                ? 'bg-amber-900/60 text-amber-200 border border-amber-700 font-semibold'
                : 'bg-slate-800/80 text-amber-400 hover:bg-slate-800'
            }`}
          >
            High ({countBySeverity.HIGH})
          </button>
          <button
            onClick={() => setSeverityFilter('MEDIUM')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
              severityFilter === 'MEDIUM'
                ? 'bg-yellow-900/60 text-yellow-200 border border-yellow-700 font-semibold'
                : 'bg-slate-800/80 text-yellow-400 hover:bg-slate-800'
            }`}
          >
            Medium ({countBySeverity.MEDIUM})
          </button>
        </div>
      </div>

      {/* Search and Secondary Filter */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-3.5 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-xs">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by title, rule ID, stream ID..."
            className="w-full bg-[#0A0E17] border border-slate-700/80 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>Confidence:</span>
          <select
            value={confidenceFilter}
            onChange={(e) => setConfidenceFilter(e.target.value as any)}
            className="bg-[#0A0E17] border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="ALL">All Confidence Levels</option>
            <option value="COMPLETE">Complete Evidence</option>
            <option value="PARTIAL">Partial Evidence</option>
            <option value="INSUFFICIENT">Insufficient</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {filteredFindings.length > 0 ? (
          filteredFindings.map((finding) => {
            const isSelected = selectedFindingId === finding.id;
            const snippet = getRemediationSnippet(finding);

            return (
              <div
                key={finding.id}
                className={`bg-[#0F1623] border rounded-xl p-5 space-y-4 transition-all shadow-xs ${
                  isSelected
                    ? 'border-cyan-500 ring-1 ring-cyan-500/40 bg-[#121B2C]'
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-slate-800/80 pb-3.5">
                  <div className="flex items-center gap-3">
                    <span className="font-mono font-bold text-xs px-2 py-0.5 rounded bg-[#0A0E17] border border-slate-700 text-cyan-300">
                      {finding.id}
                    </span>
                    <h3 className="text-base font-bold text-white tracking-tight">
                      {finding.title}
                    </h3>
                  </div>

                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={finding.severity} size="md" />
                    <ConfidenceBadge confidence={finding.confidence} />
                  </div>
                </div>

                {/* Evidence & Technical Root Cause */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  {/* Left: What was observed */}
                  <div className="p-3.5 bg-[#0A0E17] border border-slate-800 rounded-lg space-y-2">
                    <div className="flex items-center justify-between text-slate-400 font-sans">
                      <span className="font-semibold uppercase text-[10px]">Extracted Evidence Statement</span>
                      <button
                        onClick={() => {
                          onSelectSession(finding.affectedSessionId);
                          onNavigateTab('sessions');
                        }}
                        className="text-cyan-400 hover:underline flex items-center gap-1 cursor-pointer text-[11px]"
                      >
                        <span>Stream {finding.affectedSessionId}</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>

                    <p className="text-slate-200 text-xs font-sans leading-relaxed">
                      {finding.evidenceStatement}
                    </p>

                    <div className="pt-2 border-t border-slate-800/70 flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
                      <span>Frames:</span>
                      {finding.evidenceIds.map((eid) => (
                        <span key={eid} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300">
                          {eid}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Right: Authoritative Standard & Impact */}
                  <div className="p-3.5 bg-[#0A0E17] border border-slate-800 rounded-lg space-y-2">
                    <div className="text-slate-400 font-sans font-semibold uppercase text-[10px] flex items-center gap-1.5">
                      <BookOpen className="w-3.5 h-3.5 text-blue-400" />
                      <span>Authoritative RFC / NIST Standard</span>
                    </div>

                    <div className="text-cyan-300 font-bold text-xs">
                      {finding.standardReference} · {finding.ruleTitle}
                    </div>

                    <p className="text-slate-300 text-xs font-sans leading-relaxed">
                      {finding.technicalReason}
                    </p>
                  </div>
                </div>

                {/* Copyable Remediation Configuration Box */}
                <div className="p-3.5 bg-[#0A0E17] border border-slate-800 rounded-lg space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-emerald-400 text-xs font-semibold">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Recommended Server Configuration Fix</span>
                      <span className="text-[11px] text-slate-400 font-normal">
                        (Priority #{finding.priorityOrder} · Complexity: {finding.remediationComplexity})
                      </span>
                    </div>

                    <button
                      onClick={() => handleCopy(snippet, finding.id)}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors cursor-pointer border border-slate-700"
                    >
                      {copiedId === finding.id ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-300">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-slate-400" />
                          <span>Copy Config</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div className="p-3 bg-[#05080E] border border-slate-800 rounded-lg font-mono text-[11px] text-slate-200 overflow-x-auto">
                    <pre>{snippet}</pre>
                  </div>
                </div>

                {/* Action Bar */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => {
                        onSelectSession(finding.affectedSessionId);
                        onNavigateTab('sessions');
                      }}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      <Layers className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Inspect Session ({finding.affectedSessionId})</span>
                    </button>

                    <button
                      onClick={() => {
                        onSelectFinding(finding.id);
                        onNavigateTab('ai_reasoning');
                      }}
                      className="px-3 py-1.5 bg-cyan-950/50 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/70 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Explain with AI</span>
                    </button>
                  </div>

                  <span className="text-[11px] font-mono text-slate-400">
                    Rule ID: {finding.ruleId}
                  </span>
                </div>
              </div>
            );
          })
        ) : (
          <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-12 text-center text-slate-400 text-xs">
            No security findings match your current search or severity filter.
          </div>
        )}
      </div>
    </div>
  );
};
