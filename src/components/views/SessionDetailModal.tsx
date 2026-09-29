import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  AlertTriangle,
  ArrowRight,
  Clock,
  Server,
  FileCode2,
  Cpu,
  Layers,
  CheckCircle2,
  ExternalLink,
  GitBranch
} from 'lucide-react';
import { EmailSession, ProtocolEvent } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  session: EmailSession | null;
  onClose: () => void;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectFinding: (findingId: string) => void;
}

export const SessionDetailModal: React.FC<Props> = ({
  session,
  onClose,
  onNavigateTab,
  onSelectFinding
}) => {
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  if (!session) return null;

  const tls = session.tlsHandshake;
  const cert = tls?.certificate;
  const events = session.protocolEvents || [];
  const selectedEvent = events.find(e => e.id === selectedEventId) || events[0];

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-3 sm:p-6 overflow-y-auto">
      <div className="bg-[#0B0F17] border border-slate-700/80 rounded-lg max-w-5xl w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden my-auto animate-in fade-in zoom-in-95 duration-150">
        {/* Top Header */}
        <div className="p-4 px-6 border-b border-slate-800 bg-[#080C14] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="w-8 h-8 rounded bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 flex items-center justify-center font-mono font-bold text-xs">
              {session.protocol}
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white font-mono">{session.id}</h2>
                <span className="text-xs text-slate-400 font-mono">
                  {session.serverHostname || `${session.destIp}:${session.destPort}`}
                </span>
                <SeverityBadge severity={session.risk} />
                <ConfidenceBadge confidence={session.evidenceConfidence} />
              </div>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                Observed in PCAP: {session.pcapId} · Timestamp: {session.timestamp}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                onNavigateTab('ai_reasoning');
                onClose();
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/80 rounded text-xs font-semibold cursor-pointer"
            >
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Analyze with AI</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Section 10: Session Overview */}
          <div className="bg-[#080C14] border border-slate-800/90 rounded p-4">
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-3 font-semibold">
              Session Overview & Endpoint Topology
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Client Endpoint</span>
                <span className="text-slate-200 tabular-nums font-semibold">
                  {session.sourceIp}:{session.sourcePort}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Server Endpoint</span>
                <span className="text-slate-200 tabular-nums font-semibold">
                  {session.destIp}:{session.destPort}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">STARTTLS State</span>
                <span className={session.startTlsNegotiated ? 'text-emerald-400 font-semibold' : 'text-amber-400'}>
                  {session.startTlsNegotiated
                    ? 'Negotiated (Cleartext Upgraded)'
                    : session.startTlsAdvertised
                    ? 'Advertised (Not Requested)'
                    : 'Not Advertised / Plaintext'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Session Duration</span>
                <span className="text-slate-200 tabular-nums">{session.durationSec} seconds</span>
              </div>
            </div>

            {session.bannerText && (
              <div className="mt-3 pt-3 border-t border-slate-800/80">
                <span className="text-slate-500 block text-[10px] font-mono uppercase mb-1">
                  Extracted Protocol Banner:
                </span>
                <div className="p-2 bg-[#05080E] rounded border border-slate-800 text-xs font-mono text-cyan-300">
                  {session.bannerText}
                </div>
              </div>
            )}
          </div>

          {/* Section 11: TLS Handshake & Cryptography Dissection */}
          <div className="bg-[#080C14] border border-slate-800/90 rounded p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white tracking-tight">
                  Cryptographic Handshake & X.509 Analysis
                </h3>
              </div>
              {tls && (
                <span
                  className={`text-xs font-mono px-2 py-0.5 rounded border font-bold ${
                    tls.isDeprecatedVersion
                      ? 'bg-rose-950/40 text-rose-400 border-rose-800/60'
                      : 'bg-emerald-950/40 text-emerald-400 border-emerald-800/60'
                  }`}
                >
                  {tls.negotiatedVersion} · {tls.isDeprecatedVersion ? 'DEPRECATED' : 'ACTIVE'}
                </span>
              )}
            </div>

            {tls ? (
              <div className="space-y-4 text-xs font-mono">
                {/* Protocol Version & Cipher Suite */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3 bg-[#05080E] border border-slate-800 rounded">
                    <span className="text-slate-500 block text-[10px] uppercase">TLS Version Policy</span>
                    <div className="mt-1 flex items-center justify-between">
                      <span className="text-sm font-bold text-white">{tls.negotiatedVersion}</span>
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                          tls.isDeprecatedVersion
                            ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                            : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                        }`}
                      >
                        {tls.isDeprecatedVersion ? 'DEPRECATED' : 'CONFORMING'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 font-sans">
                      {tls.isDeprecatedVersion
                        ? 'Observed in Server Hello (0x0301). Deprecated by RFC 8996; RFC 9325 (BCP 195) mandates TLS 1.2 or TLS 1.3.'
                        : 'Observed in Server Hello. Conforms to current IETF BCP 195 recommendations for secure TLS transport.'}
                    </p>
                  </div>

                  <div className="p-3 bg-[#05080E] border border-slate-800 rounded">
                    <span className="text-slate-500 block text-[10px] uppercase">Selected Cipher Suite</span>
                    <div className="mt-1 flex items-center justify-between">
                      <span className="text-sm font-bold text-white truncate max-w-[280px]" title={tls.cipherSuite.ianaName}>
                        {tls.cipherSuite.ianaName}
                      </span>
                      <span className="text-[10px] text-slate-400">({tls.cipherSuite.rfcCode})</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 font-sans">
                      Encryption: {tls.cipherSuite.encryption} · MAC: {tls.cipherSuite.mac}
                    </p>
                  </div>
                </div>

                {/* Key Exchange & Forward Secrecy */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3 bg-[#05080E] border border-slate-800 rounded">
                    <span className="text-slate-500 block text-[10px] uppercase">Key Exchange Mechanism</span>
                    <div className="mt-1 text-sm font-bold text-white">{tls.cipherSuite.keyExchange}</div>
                    <p className="text-[11px] text-slate-400 mt-1 font-sans">
                      {tls.forwardSecrecy
                        ? 'Ephemeral Diffie-Hellman parameters negotiated.'
                        : 'Static RSA key exchange observed. No ephemeral keys.'}
                    </p>
                  </div>

                  <div className="p-3 bg-[#05080E] border border-slate-800 rounded">
                    <span className="text-slate-500 block text-[10px] uppercase">Perfect Forward Secrecy (PFS)</span>
                    <div className="mt-1 flex items-center gap-2">
                      <span
                        className={`text-sm font-bold ${
                          tls.forwardSecrecy ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        {tls.forwardSecrecy ? 'VERIFIED (PROVIDED)' : 'NOT PROVIDED'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 font-sans">
                      {tls.forwardSecrecy
                        ? 'Past sessions cannot be decrypted if server private key is compromised.'
                        : 'Compromise of server private key allows retroactive decryption of recorded PCAPs.'}
                    </p>
                  </div>
                </div>

                {/* X.509 Certificate Breakdown */}
                {cert ? (
                  <div className="p-4 bg-[#05080E] border border-slate-800 rounded space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                      <span className="text-xs font-bold text-slate-200">
                        Presented X.509 Server Certificate
                      </span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          cert.isExpired
                            ? 'bg-rose-950/60 text-rose-300 border border-rose-800/80'
                            : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/80'
                        }`}
                      >
                        CHAIN STATUS: {cert.chainStatus}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                      <div>
                        <span className="text-slate-500 block">Subject DN</span>
                        <span className="text-slate-200 break-all">{cert.subject}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Issuer DN</span>
                        <span className="text-slate-200 break-all">{cert.issuer}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Validity Period</span>
                        <span className="text-slate-300">
                          {cert.validFrom} → {cert.validUntil}
                        </span>
                        {cert.isExpired ? (
                          <span className="text-rose-400 font-bold block">
                            Expired {Math.abs(cert.daysUntilExpiry)} days ago
                          </span>
                        ) : (
                          <span className="text-emerald-400 block">
                            Valid ({cert.daysUntilExpiry} days remaining)
                          </span>
                        )}
                      </div>
                      <div>
                        <span className="text-slate-500 block">Cryptographic Key & Signature</span>
                        <span className="text-slate-200">
                          {cert.publicKeyAlgorithm} {cert.keyLengthBits}-bit · {cert.signatureAlgorithm}
                        </span>
                        {cert.isWeakSignature && (
                          <span className="text-rose-400 font-bold block">
                            Weak Signature Algorithm (SHA-1 Collision Risk)
                          </span>
                        )}
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 block text-[10px]">SHA-256 Fingerprint</span>
                      <span className="text-slate-400 text-[10px] break-all select-all">
                        {cert.fingerprintSha256}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="p-3 bg-[#05080E] border border-slate-800 rounded text-slate-400 text-xs">
                    No X.509 certificate frames captured in this session trace.
                  </div>
                )}
              </div>
            ) : (
              <div className="p-4 bg-rose-950/20 border border-rose-900/40 rounded text-xs font-mono space-y-2">
                <div className="flex items-center gap-2 text-rose-400 font-bold">
                  <Unlock className="w-4 h-4" />
                  <span>UNENCRYPTED PLAINTEXT PROTOCOL STREAM</span>
                </div>
                <p className="text-slate-300 font-sans leading-relaxed">
                  No TLS encapsulation was negotiated. All application commands, usernames, and passwords were exchanged in cleartext on standard port {session.destPort}.
                </p>
                {session.plaintextCredentialsExposed && (
                  <div className="p-2 bg-rose-950/40 border border-rose-800 rounded text-rose-300 font-bold">
                    CRITICAL: Cleartext authentication credentials extracted from packet payload.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Section 10: Interactive Protocol Timeline */}
          <div className="bg-[#080C14] border border-slate-800/90 rounded p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" />
                  <span>Reconstructed Email Protocol Dialogue Timeline</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Click any packet event to inspect raw payload preview and packet frame metadata.
                </p>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {events.length} Events Logged
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* Event List */}
              <div className="lg:col-span-7 space-y-1.5 max-h-80 overflow-y-auto pr-1">
                {events.map((evt) => {
                  const isSelected = selectedEvent?.id === evt.id;
                  return (
                    <div
                      key={evt.id}
                      onClick={() => setSelectedEventId(evt.id)}
                      className={`p-2.5 rounded border text-xs font-mono cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-cyan-950/50 border-cyan-600 text-white'
                          : evt.isWeaknessOrAnomaly
                          ? 'bg-rose-950/20 border-rose-800/50 text-rose-300 hover:bg-rose-950/30'
                          : 'bg-[#05080E] border-slate-800/80 text-slate-300 hover:bg-slate-800/40'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-slate-500 tabular-nums">
                            +{evt.relativeMs}ms
                          </span>
                          <span className="font-semibold text-slate-200">{evt.title}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 tabular-nums">
                          Pkt #{evt.packetNumber}
                        </span>
                      </div>
                      {evt.payloadPreview && (
                        <p className="text-[10px] text-slate-400 mt-1 truncate font-mono">
                          {evt.payloadPreview}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Selected Event Details Panel */}
              <div className="lg:col-span-5 p-3.5 bg-[#05080E] border border-slate-800 rounded flex flex-col justify-between text-xs font-mono">
                <div>
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                    <span className="text-[10px] text-slate-500 uppercase">Event Detail</span>
                    <span className="text-cyan-400 font-bold">Packet #{selectedEvent?.packetNumber}</span>
                  </div>

                  <div className="mt-2.5 space-y-2">
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Stage</span>
                      <span className="text-slate-200 font-bold">{selectedEvent?.stage}</span>
                    </div>

                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Direction</span>
                      <span className="text-slate-300">{selectedEvent?.direction}</span>
                    </div>

                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Technical Detail</span>
                      <p className="text-slate-200 leading-relaxed font-sans text-xs">
                        {selectedEvent?.detail}
                      </p>
                    </div>

                    {selectedEvent?.payloadPreview && (
                      <div>
                        <span className="text-slate-500 text-[10px] uppercase block">Payload Sample</span>
                        <pre className="p-2 bg-[#020408] rounded border border-slate-800 text-[10px] text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                          {selectedEvent.payloadPreview}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>

                <div className="mt-3 pt-2 border-t border-slate-800/80 text-[10px] text-slate-500">
                  TCP Stream Index: {selectedEvent?.tcpStreamIndex}
                </div>
              </div>
            </div>
          </div>

          {/* Evidence-Linked Findings in this Session */}
          <div className="bg-[#080C14] border border-slate-800/90 rounded p-4 space-y-3">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block font-semibold">
              Findings Triggered in this Session ({session.findingsIds.length}):
            </span>
            <div className="flex flex-wrap gap-2">
              {session.findingsIds.map(fid => (
                <button
                  key={fid}
                  onClick={() => {
                    onSelectFinding(fid);
                    onNavigateTab('findings');
                    onClose();
                  }}
                  className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded text-xs font-mono text-cyan-300 flex items-center gap-1.5 cursor-pointer transition-colors"
                >
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  <span>Inspect {fid}</span>
                  <ExternalLink className="w-3 h-3 text-slate-500" />
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 bg-[#080C14] border-t border-slate-800 flex items-center justify-between">
          <button
            onClick={() => {
              onNavigateTab('evidence');
              onClose();
            }}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
          >
            <GitBranch className="w-3.5 h-3.5" />
            <span>View Evidence Lineage in Intelligence Graph</span>
          </button>

          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded transition-colors cursor-pointer"
          >
            Close Investigation
          </button>
        </div>
      </div>
    </div>
  );
};
