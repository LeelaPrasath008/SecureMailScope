import React, { useState } from 'react';
import {
  Layers,
  Search,
  Filter,
  Lock,
  Unlock,
  AlertTriangle,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  CheckCircle2,
  Clock,
  Maximize2,
  Server,
  FileCode2,
  Cpu,
  ChevronRight,
  ShieldAlert,
  GitBranch,
  Copy,
  Check,
  HelpCircle,
  ShieldX,
  FileSearch
} from 'lucide-react';
import { CryptographicEvidence, DemoScenario, EmailSession, ProtocolType, SeverityLevel } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { SessionDetailModal } from './SessionDetailModal';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  sessions: EmailSession[];
  scenario?: DemoScenario;
  evidenceList?: CryptographicEvidence[];
  selectedSessionId: string | null;
  onSelectSession: (id: string | null) => void;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectFinding: (findingId: string) => void;
}

type InspectorTab = 'handshake' | 'certificate' | 'events' | 'evidence' | 'overview';

export const SessionsView: React.FC<Props> = ({
  sessions,
  scenario,
  evidenceList = [],
  selectedSessionId,
  onSelectSession,
  onNavigateTab,
  onSelectFinding
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<ProtocolType | 'ALL'>('ALL');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>('handshake');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Default to first session if none selected
  const activeSessionId = selectedSessionId || (sessions[0]?.id ?? null);
  const activeSession = sessions.find((s) => s.id === activeSessionId) || sessions[0] || null;

  const sessionEvidence = activeSession
    ? evidenceList.filter((e) => activeSession.evidenceIds?.includes(e.id))
    : [];

  const filteredSessions = sessions.filter((s) => {
    if (protocolFilter !== 'ALL' && s.protocol !== protocolFilter) return false;
    if (severityFilter !== 'ALL' && s.risk !== severityFilter) return false;
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      const matchId = s.id.toLowerCase().includes(q);
      const matchIp = s.sourceIp.toLowerCase().includes(q) || s.destIp.toLowerCase().includes(q);
      const matchHost = (s.serverHostname || '').toLowerCase().includes(q);
      const matchCipher = (s.tlsHandshake?.cipherSuite.ianaName || '').toLowerCase().includes(q);
      const matchTls = (s.tlsHandshake?.negotiatedVersion || '').toLowerCase().includes(q);
      if (!matchId && !matchIp && !matchHost && !matchCipher && !matchTls) return false;
    }
    return true;
  });

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 1800);
  };

  const tls = activeSession?.tlsHandshake;
  const cert = tls?.certificate;

  // OUT OF SCOPE / Zero Reconstructed Email Sessions Guard
  if (sessions.length === 0) {
    const classification = scenario?.pcapMetadata?.protocolClassification;
    const protocols = classification?.detectedProtocols || [];
    return (
      <div className="p-4 sm:p-6 space-y-5 max-w-7xl mx-auto">
        <div className="bg-gradient-to-r from-amber-950/40 via-[#0F1623] to-[#0A0E17] border border-amber-600/50 rounded-xl p-6 space-y-4 shadow-lg">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-amber-950/80 border border-amber-600/70 rounded-xl text-amber-400 shrink-0">
              <ShieldX className="w-8 h-8" />
            </div>
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                  Forensic Scope Validation Layer
                </span>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-md bg-amber-950 text-amber-300 border border-amber-700">
                  ASSESSMENT STATUS: OUT OF SCOPE
                </span>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700">
                  POSTURE: NOT ASSESSABLE
                </span>
              </div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                No Email Communication Streams Reconstructed
              </h2>
              <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
                {scenario?.scopeValidation?.scopeReason || 'No SMTP, IMAP, POP3, SMTPS, IMAPS, or POP3S traffic was identified in this packet capture.'}
                {' '}Session reconstruction and cryptographic state machine reassembly are strictly executed only when email traffic is present.
              </p>
            </div>
          </div>

          {/* Golden Forensic Rule Callout */}
          <div className="p-3.5 bg-[#080C14] border border-amber-800/40 rounded-lg text-xs flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-slate-300 leading-relaxed">
              <strong className="text-amber-300 font-mono">GOLDEN FORENSIC RULE ENFORCED:</strong>{' '}
              Absence of Evidence ≠ Secure. Absence of Evidence = NOT ASSESSABLE.
              Because 0 email streams were detected, SecureMailScope refuses to issue false security certifications or fabricate mock email sessions.
            </div>
          </div>

          {/* Protocol Classification Table */}
          {protocols.length > 0 && (
            <div className="space-y-2 pt-2">
              <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 block">
                Observed Protocol Classification (All Layers Dissected):
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                {protocols.map((p, idx) => (
                  <div key={idx} className="bg-[#0A0E17] border border-slate-800 rounded-lg p-3">
                    <span className="text-slate-400 text-[10px] uppercase font-mono block">{p.protocol}</span>
                    <span className="text-white font-mono font-bold text-base tabular-nums">{p.packetCount.toLocaleString()}</span>
                    <span className="text-[10px] text-slate-500 block">packets ({classification?.confidence || 'HIGH'} confidence)</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Navigation Action */}
          <div className="pt-2 flex flex-wrap items-center gap-3">
            <button
              onClick={() => onNavigateTab('dashboard')}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center gap-2 cursor-pointer transition-colors"
            >
              <Layers className="w-4 h-4" />
              <span>Return to Assessment Dashboard</span>
            </button>
            <button
              onClick={() => onNavigateTab('pcap_analysis')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-2 cursor-pointer transition-colors"
            >
              <FileSearch className="w-4 h-4 text-cyan-400" />
              <span>Inspect Raw Ingestion Pipeline</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 sm:p-6 space-y-4 max-w-7xl mx-auto">
      {/* Top Filter and Search Bar */}
      <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-xs">
        <div className="flex flex-col sm:flex-row flex-1 items-stretch sm:items-center gap-2.5">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search stream ID, IP address, cipher..."
              className="w-full bg-[#0A0E17] border border-slate-700/80 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Protocol Filter Tabs (Touch Friendly) */}
          <div className="flex items-center gap-1 bg-[#0A0E17] border border-slate-800 p-0.5 rounded-lg overflow-x-auto shrink-0">
            {(['ALL', 'SMTP', 'IMAP', 'POP3'] as const).map((proto) => (
              <button
                key={proto}
                onClick={() => setProtocolFilter(proto)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                  protocolFilter === proto
                    ? 'bg-slate-800 text-cyan-300 font-semibold shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {proto}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Risk:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as any)}
              className="bg-[#0A0E17] border border-slate-700 rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <span className="text-xs font-mono text-slate-400 pl-2 border-l border-slate-800">
            Showing <strong className="text-slate-200 tabular-nums">{filteredSessions.length}</strong> of {sessions.length}
          </span>
        </div>
      </div>

      {/* Master-Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Master: Session List Column (5 cols) */}
        <div className="lg:col-span-5 bg-[#0F1623] border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col max-h-[340px] lg:max-h-[calc(100vh-180px)]">
          <div className="p-3.5 bg-[#0A0E17] border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300">Reconstructed Streams</span>
            <span className="text-[11px] text-slate-400">Click to inspect</span>
          </div>

          <div className="overflow-y-auto divide-y divide-slate-800/60 p-1">
            {filteredSessions.length > 0 ? (
              filteredSessions.map((session) => {
                const isSelected = activeSession?.id === session.id;
                return (
                  <div
                    key={session.id}
                    onClick={() => onSelectSession(session.id)}
                    className={`p-3 rounded-lg transition-all cursor-pointer text-xs ${
                      isSelected
                        ? 'bg-cyan-950/40 border border-cyan-800/70 text-slate-100 shadow-xs'
                        : 'hover:bg-slate-800/50 text-slate-300 border border-transparent'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                          session.protocol === 'SMTP'
                            ? 'bg-blue-950/70 text-blue-300 border border-blue-800/60'
                            : session.protocol === 'IMAP'
                            ? 'bg-purple-950/70 text-purple-300 border border-purple-800/60'
                            : 'bg-amber-950/70 text-amber-300 border border-amber-800/60'
                        }`}>
                          {session.protocol}
                        </span>
                        <span className="font-mono font-bold text-white text-xs">{session.id}</span>
                      </div>
                      <SeverityBadge severity={session.risk} size="sm" />
                    </div>

                    <div className="text-[11px] text-slate-400 font-mono flex items-center justify-between mb-1">
                      <span className="truncate max-w-[180px]">{session.serverHostname || `${session.destIp}:${session.destPort}`}</span>
                      <span>{session.timestamp}</span>
                    </div>

                    <div className="flex items-center justify-between pt-1 border-t border-slate-800/40 text-[10px] font-mono">
                      <span className="text-slate-400">
                        {session.tlsHandshake ? (
                          <span className={session.tlsHandshake.isDeprecatedVersion ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                            {session.tlsHandshake.negotiatedVersion}
                          </span>
                        ) : (
                          <span className="text-slate-400">Plaintext</span>
                        )}
                      </span>
                      <span className="text-slate-400 truncate max-w-[140px]">
                        {session.tlsHandshake?.cipherSuite.ianaName || 'No TLS'}
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="p-8 text-center text-slate-400 text-xs">
                No sessions match the current search or filters.
              </div>
            )}
          </div>
        </div>

        {/* Detail: Session Inspector Column (7 cols) */}
        {activeSession ? (
          <div className="lg:col-span-7 bg-[#0F1623] border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col max-h-[calc(100vh-180px)]">
            {/* Inspector Header */}
            <div className="p-4 bg-[#0A0E17] border-b border-slate-800 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5 min-w-0">
                <span className="w-8 h-8 rounded-lg bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 flex items-center justify-center font-mono font-bold text-xs shrink-0">
                  {activeSession.protocol}
                </span>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white font-mono text-sm">{activeSession.id}</span>
                    <SeverityBadge severity={activeSession.risk} size="sm" />
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono truncate">
                    {activeSession.sourceIp}:{activeSession.sourcePort} → {activeSession.destIp}:{activeSession.destPort} ({activeSession.serverHostname || 'Unknown Host'})
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => {
                    onNavigateTab('ai_reasoning');
                  }}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 bg-cyan-950/50 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/70 rounded-lg text-xs font-medium cursor-pointer transition-colors"
                >
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="hidden sm:inline">AI Analysis</span>
                </button>

                <button
                  onClick={() => setIsModalOpen(true)}
                  className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
                  title="Expand to Fullscreen View"
                >
                  <Maximize2 className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Inspector Navigation Tabs */}
            <div className="flex items-center gap-1 px-4 pt-2.5 border-b border-slate-800 bg-[#0A0E17]/60 overflow-x-auto">
              {[
                { id: 'handshake' as InspectorTab, label: 'TLS Handshake & Ciphers' },
                { id: 'certificate' as InspectorTab, label: 'X.509 Certificate' },
                { id: 'events' as InspectorTab, label: 'Protocol Dialogue' },
                { id: 'evidence' as InspectorTab, label: 'Raw Wire Evidence' },
                { id: 'overview' as InspectorTab, label: 'Overview & Banner' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setInspectorTab(tab.id)}
                  className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors cursor-pointer whitespace-nowrap ${
                    inspectorTab === tab.id
                      ? 'border-cyan-400 text-cyan-300 font-semibold'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Inspector Content Body */}
            <div className="p-4 sm:p-5 overflow-y-auto space-y-4 flex-1">
              {/* Tab 1: TLS Handshake & Ciphers */}
              {inspectorTab === 'handshake' && (
                <div className="space-y-4">
                  {tls ? (
                    <>
                      {/* TLS Status Highlight */}
                      <div className={`p-4 rounded-xl border ${
                        tls.isDeprecatedVersion
                          ? 'bg-rose-950/20 border-rose-900/40 text-rose-300'
                          : 'bg-emerald-950/20 border-emerald-900/40 text-emerald-300'
                      }`}>
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-xs uppercase tracking-wider">
                            Negotiated Version
                          </span>
                          <span className="text-xs font-mono font-bold px-2 py-0.5 rounded border border-current">
                            {tls.negotiatedVersion}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                          {tls.isDeprecatedVersion
                            ? 'Critical Flaw: Negotiated version is deprecated under RFC 8996 (BCP 195). Modern email security requires TLS 1.2 or TLS 1.3.'
                            : 'Conforming TLS version negotiated in Server Hello handshake.'}
                        </p>
                      </div>

                      {/* Cipher Suite Card */}
                      <div className="bg-[#0A0E17] border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-slate-400 font-semibold uppercase text-[11px]">Selected Cipher Suite</span>
                          <span className="text-[11px] text-slate-400">RFC Code: {tls.cipherSuite.rfcCode}</span>
                        </div>

                        <div className="p-3 bg-[#05080E] border border-slate-800 rounded-lg flex items-center justify-between gap-2">
                          <span className="text-white font-bold text-sm truncate">{tls.cipherSuite.ianaName}</span>
                          <button
                            onClick={() => handleCopy(tls.cipherSuite.ianaName, 'cipher')}
                            className="p-1 hover:text-cyan-300 text-slate-400 cursor-pointer"
                            title="Copy cipher suite name"
                          >
                            {copiedText === 'cipher' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>

                        <div className="grid grid-cols-2 gap-3 pt-2">
                          <div>
                            <span className="text-slate-400 block text-[10px] uppercase">Key Exchange</span>
                            <span className="text-slate-200 font-bold">{tls.cipherSuite.keyExchange}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[10px] uppercase">Forward Secrecy (PFS)</span>
                            <span className={tls.forwardSecrecy ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                              {tls.forwardSecrecy ? 'Provided (Ephemeral)' : 'None (Static RSA)'}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[10px] uppercase">Symmetric Encryption</span>
                            <span className="text-slate-200">{tls.cipherSuite.encryption}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[10px] uppercase">Integrity MAC</span>
                            <span className="text-slate-200">{tls.cipherSuite.mac}</span>
                          </div>
                        </div>

                        {tls.cipherSuite.isWeak && (
                          <div className="mt-2 p-2.5 bg-amber-950/30 border border-amber-800/60 rounded-lg text-amber-300 text-xs font-sans">
                            <strong>Weak Cipher Advisory:</strong> {tls.cipherSuite.weaknessReason || 'Cipher suite violates modern BCP 195 recommendations.'}
                          </div>
                        )}
                      </div>
                    </>
                  ) : (
                    <div className="p-8 text-center bg-[#0A0E17] border border-slate-800 rounded-xl space-y-2">
                      <Unlock className="w-8 h-8 text-rose-400 mx-auto" />
                      <h4 className="text-sm font-bold text-white">No TLS Handshake Observed</h4>
                      <p className="text-xs text-slate-400 max-w-md mx-auto">
                        This email session was conducted in cleartext. Credentials and message headers were transmitted without cryptographic protection.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: X.509 Certificate */}
              {inspectorTab === 'certificate' && (
                <div className="space-y-4">
                  {cert ? (
                    <div className="bg-[#0A0E17] border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                        <span className="text-xs font-semibold text-slate-300">Server X.509 Certificate</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          cert.isExpired ? 'bg-rose-950/60 text-rose-400 border border-rose-800/60' : 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/60'
                        }`}>
                          {cert.isExpired ? 'EXPIRED' : 'VALID WINDOW'}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <span className="text-slate-400 block text-[10px] uppercase">Subject Common Name</span>
                          <span className="text-cyan-300 font-bold">{cert.subjectCommonName}</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block text-[10px] uppercase">Issuer Common Name</span>
                          <span className="text-slate-200">{cert.issuerCommonName}</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block text-[10px] uppercase">Valid From</span>
                          <span className="text-slate-300">{cert.validFrom}</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block text-[10px] uppercase">Valid Until</span>
                          <span className={cert.isExpired ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                            {cert.validUntil} ({cert.daysUntilExpiry} days)
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400 block text-[10px] uppercase">Public Key Algorithm</span>
                          <span className="text-slate-200">{cert.publicKeyAlgorithm} ({cert.keyLengthBits}-bit)</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block text-[10px] uppercase">Signature Algorithm</span>
                          <span className="text-slate-200">{cert.signatureAlgorithm}</span>
                        </div>
                      </div>

                      <div className="pt-2 border-t border-slate-800">
                        <span className="text-slate-400 block text-[10px] uppercase mb-1">SHA-256 Fingerprint</span>
                        <div className="p-2 bg-[#05080E] rounded text-[11px] text-slate-300 break-all select-all">
                          {cert.fingerprintSha256}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 text-center bg-[#0A0E17] border border-slate-800 rounded-xl text-slate-400 text-xs">
                      No X.509 certificate presented in this session.
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: Protocol Dialogue & Events */}
              {inspectorTab === 'events' && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="text-slate-400 text-xs font-sans">
                    Chronological sequence of extracted email protocol events and state transitions:
                  </div>

                  <div className="space-y-2">
                    {activeSession.protocolEvents && activeSession.protocolEvents.length > 0 ? (
                      activeSession.protocolEvents.map((evt, idx) => (
                        <div
                          key={evt.id || idx}
                          className="p-3 bg-[#0A0E17] border border-slate-800 rounded-lg flex items-start justify-between gap-3"
                        >
                          <div className="space-y-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-slate-400">Packet #{evt.packetNumber}</span>
                              <span className="text-cyan-400 font-bold">{evt.title}</span>
                              <span className={`text-[9px] px-1.5 py-0.2 rounded font-sans ${
                                evt.isWeaknessOrAnomaly
                                  ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                                  : 'bg-slate-800 text-slate-400'
                              }`}>
                                {evt.stage}
                              </span>
                            </div>
                            <div className="text-slate-200 text-xs font-mono break-all">
                              {evt.payloadPreview || evt.detail}
                            </div>
                          </div>
                          <span className="text-slate-400 text-[10px] shrink-0 font-sans">{evt.direction}</span>
                        </div>
                      ))
                    ) : (
                      <div className="p-4 text-center text-slate-400 text-xs">
                        No individual protocol events recorded for this session.
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Tab 4: Raw Wire Evidence */}
              {inspectorTab === 'evidence' && (
                <div className="space-y-3">
                  <div className="text-xs text-slate-400 font-sans">
                    Forensic evidence frames extracted directly from capture PCAP:
                  </div>

                  {sessionEvidence.length > 0 ? (
                    sessionEvidence.map((ev) => (
                      <div key={ev.id} className="bg-[#0A0E17] border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-cyan-300 font-bold">{ev.id}</span>
                          <span className="text-slate-400 text-[10px]">Frame #{ev.packetFrameNumbers.join(', ')}</span>
                        </div>

                        {ev.hexDumpSample && (
                          <div className="p-3 bg-[#05080E] border border-slate-800 rounded-lg overflow-x-auto text-[11px] text-slate-300 leading-relaxed font-mono">
                            <pre>{ev.hexDumpSample}</pre>
                          </div>
                        )}

                        <div className="text-slate-300 text-xs font-sans">
                          {ev.rawObservation}
                        </div>

                        <div className="text-slate-400 text-[11px] font-sans">
                          {ev.confidenceExplanation}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="p-6 text-center text-slate-400 text-xs bg-[#0A0E17] rounded-xl border border-slate-800">
                      Standard evidence extraction bound to session stream.
                    </div>
                  )}
                </div>
              )}

              {/* Tab 5: Overview & Banner */}
              {inspectorTab === 'overview' && (
                <div className="space-y-4 font-mono text-xs">
                  <div className="bg-[#0A0E17] border border-slate-800 rounded-xl p-4 space-y-3">
                    <span className="text-xs font-semibold text-slate-300 font-sans block">Session Parameters</span>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase">Client IP / Port</span>
                        <span className="text-white font-bold">{activeSession.sourceIp}:{activeSession.sourcePort}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase">Server IP / Port</span>
                        <span className="text-white font-bold">{activeSession.destIp}:{activeSession.destPort}</span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase">STARTTLS State</span>
                        <span className="text-white">
                          {activeSession.startTlsNegotiated ? 'Negotiated & Upgraded' : activeSession.startTlsAdvertised ? 'Advertised' : 'None'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px] uppercase">Evidence Confidence</span>
                        <ConfidenceBadge confidence={activeSession.evidenceConfidence} />
                      </div>
                    </div>

                    {activeSession.bannerText && (
                      <div className="pt-3 border-t border-slate-800">
                        <span className="text-slate-400 block text-[10px] uppercase mb-1">Server Banner</span>
                        <div className="p-2.5 bg-[#05080E] rounded border border-slate-800 text-cyan-300 font-mono text-xs">
                          {activeSession.bannerText}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : null}
      </div>

      {/* Optional Fullscreen Modal if user clicked expand */}
      {isModalOpen && activeSession && (
        <SessionDetailModal
          session={activeSession}
          onClose={() => setIsModalOpen(false)}
          onNavigateTab={onNavigateTab}
          onSelectFinding={onSelectFinding}
        />
      )}
    </div>
  );
};
