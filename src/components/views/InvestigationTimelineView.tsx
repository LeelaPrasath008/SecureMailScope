import React, { useState } from 'react';
import {
  GitBranch,
  Clock,
  AlertTriangle,
  Lock,
  Unlock,
  Layers,
  ArrowRight,
  ShieldAlert,
  Server,
  Terminal,
  Info
} from 'lucide-react';
import { DemoScenario, ProtocolEvent } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { NavigationTab } from '../layout/Sidebar';

interface Props {
  scenario: DemoScenario;
  onNavigateTab: (tab: NavigationTab) => void;
  onSelectSession: (sessionId: string) => void;
}

export const InvestigationTimelineView: React.FC<Props> = ({
  scenario,
  onNavigateTab,
  onSelectSession
}) => {
  const [selectedSessionId, setSelectedSessionId] = useState<string>(
    scenario.defaultSelectedSessionId || scenario.sessions[0]?.id || ''
  );

  const activeSession =
    scenario.sessions.find(s => s.id === selectedSessionId) || scenario.sessions[0];
  const events = activeSession?.protocolEvents || [];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-cyan-400" />
            <span>Cryptographic Attack-Path & Security Event Reconstruction</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Temporal forensic reconstruction of packet-level protocol handshakes and security weakness exposures.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Target Session:</span>
          <select
            value={selectedSessionId}
            onChange={e => setSelectedSessionId(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            {scenario.sessions.map(s => (
              <option key={s.id} value={s.id}>
                {s.id} ({s.protocol}:{s.destPort} - {s.risk})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Mandatory Evaluator Guardrail (Prompt Section 15) */}
      <div className="p-3.5 bg-[#080C14] border-l-4 border-amber-500 rounded-r border-y border-r border-slate-800 flex items-start gap-3">
        <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs">
          <span className="font-semibold text-amber-300 font-mono">FORENSIC ATTRIBUTION INTEGRITY NOTE:</span>
          <p className="text-slate-300 mt-0.5 leading-relaxed">
            This timeline reconstructs observed protocol transitions and cryptographic weakness points. SecureMailScope documents technical vulnerability exposure and does not claim evidence of active attacker exploitation unless specific attack packets (e.g. padding oracle tampering or certificate forgery) are mathematically proven in the capture.
          </p>
        </div>
      </div>

      {/* Session Metadata Banner */}
      <div className="bg-[#0B0F17] border border-slate-800 rounded p-4 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
        <div className="flex items-center gap-4">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Session</span>
            <span className="text-cyan-400 font-bold">{activeSession?.id}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Protocol</span>
            <span className="text-slate-200">{activeSession?.protocol} (Port {activeSession?.destPort})</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Endpoints</span>
            <span className="text-slate-300 tabular-nums">
              {activeSession?.sourceIp} → {activeSession?.destIp}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <SeverityBadge severity={activeSession?.risk || 'LOW'} />
          <button
            onClick={() => {
              onSelectSession(activeSession.id);
              onNavigateTab('sessions');
            }}
            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 text-xs font-mono transition-colors cursor-pointer"
          >
            Open Dissection
          </button>
        </div>
      </div>

      {/* Chronological Timeline Container */}
      <div className="bg-[#0B0F17] border border-slate-800 rounded p-6">
        <div className="relative border-l-2 border-slate-800 ml-4 pl-6 space-y-6">
          {events.length > 0 ? (
            events.map((evt, idx) => (
              <div key={evt.id} className="relative group">
                {/* Timeline Node Icon */}
                <div
                  className={`absolute -left-[31px] top-0.5 w-4 h-4 rounded-full border-2 flex items-center justify-center transition-all ${
                    evt.isWeaknessOrAnomaly
                      ? 'bg-rose-950 border-rose-500 ring-4 ring-rose-950/50'
                      : 'bg-[#0B0F17] border-cyan-500'
                  }`}
                />

                {/* Event Card */}
                <div
                  className={`p-4 rounded border text-xs font-mono transition-all ${
                    evt.isWeaknessOrAnomaly
                      ? 'bg-[#12080D] border-rose-900/60'
                      : 'bg-[#080C14] border-slate-800'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-slate-800/60 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500 tabular-nums font-semibold">
                        {evt.timestamp}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-400">
                        +{evt.relativeMs}ms
                      </span>
                      <span className="font-bold text-white text-sm font-sans">{evt.title}</span>
                    </div>

                    <div className="flex items-center gap-2 text-[11px]">
                      <span className="text-slate-500">Packet #{evt.packetNumber}</span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          evt.direction === 'SERVER_TO_CLIENT'
                            ? 'bg-blue-950/60 text-blue-300'
                            : evt.direction === 'CLIENT_TO_SERVER'
                            ? 'bg-cyan-950/60 text-cyan-300'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {evt.direction}
                      </span>
                    </div>
                  </div>

                  <p className="text-slate-300 font-sans text-xs mt-2 leading-relaxed">
                    {evt.detail}
                  </p>

                  {evt.payloadPreview && (
                    <div className="mt-2.5 p-2 bg-[#03060A] rounded border border-slate-800 text-[11px] text-cyan-300 whitespace-pre-wrap break-all">
                      {evt.payloadPreview}
                    </div>
                  )}

                  {evt.isWeaknessOrAnomaly && (
                    <div className="mt-2 pt-2 border-t border-rose-950/80 flex items-center justify-between text-[11px] text-rose-400">
                      <span className="flex items-center gap-1 font-bold">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        Security Weakness Point Identified
                      </span>
                      <button
                        onClick={() => onNavigateTab('findings')}
                        className="text-rose-300 hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        <span>Inspect Associated Finding</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))
          ) : (
            <div className="text-slate-500 text-xs font-mono py-8">
              No timeline events recorded for this session.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
