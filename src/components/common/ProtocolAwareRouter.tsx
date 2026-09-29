/**
 * SecureMailScope - Protocol-Aware Assessment Routing (SIH Innovation)
 * SECTION 10: Visual pipeline routing decision shown in the dashboard.
 * SIH 2026 Problem Statement 26159
 */

import React from 'react';
import { Mail, Globe, Car, HelpCircle, ArrowRight, ShieldCheck, ShieldAlert, CheckCircle2, XCircle } from 'lucide-react';
import { ProtocolClassificationResult, ScopeValidationResult } from '../../types/security';

interface Props {
  classification?: ProtocolClassificationResult;
  scopeValidation?: ScopeValidationResult;
  onExploreRoute?: (trafficType: string) => void;
}

export const ProtocolAwareRouter: React.FC<Props> = ({
  classification,
  scopeValidation,
  onExploreRoute
}) => {
  const activeTrafficType = scopeValidation?.routingDecision.routedTrafficType || 'Email Traffic';
  const isAccepted = scopeValidation?.isEmailInScope ?? true;
  const targetEngine = scopeValidation?.routingDecision.targetEngine || 'SecureMailScope Analysis';

  const routes = [
    {
      id: 'email',
      title: 'Email Traffic',
      protocols: 'SMTP, SMTPS, IMAP, IMAPS, POP3, POP3S',
      target: 'SecureMailScope Analysis',
      status: 'IN SCOPE',
      description: 'Dissects mail state machines, STARTTLS negotiation, ciphers, and X.509 chains.',
      icon: Mail,
      accentColor: 'cyan',
      packetCount: classification?.totalEmailPackets ?? 0,
      active: activeTrafficType === 'Email Traffic'
    },
    {
      id: 'web',
      title: 'Web Traffic',
      protocols: 'HTTP (80), HTTPS (443)',
      target: 'Web Security Engine',
      status: 'OUT OF SCOPE',
      description: 'Web application layer traffic diverted. Requires OWASP / WAF inspection.',
      icon: Globe,
      accentColor: 'indigo',
      packetCount: (classification?.counts.http ?? 0) + (classification?.counts.https ?? 0),
      active: activeTrafficType === 'Web Traffic'
    },
    {
      id: 'vehicular',
      title: 'Vehicular Traffic (ITS-G5 / V2X)',
      protocols: 'ETSI ITS-G5 (0x8947), IEEE 1609 WSMP (0x88DC), BTP CAM/DENM',
      target: 'V2X Security Gateway',
      status: 'OUT OF SCOPE',
      description: 'Automotive cooperative safety telemetry. Requires ETSI TS 102 941 PKI validation.',
      icon: Car,
      accentColor: 'amber',
      packetCount: (classification?.counts.itsG5 ?? 0) + (classification?.counts.v2x ?? 0),
      active: activeTrafficType === 'Vehicular Traffic (ITS-G5 / V2X)'
    },
    {
      id: 'unknown',
      title: 'Infrastructure & Unknown',
      protocols: 'ICMP, DNS, SSH, FTP, Unclassified Packets',
      target: 'Manual Protocol Carving',
      status: 'OUT OF SCOPE',
      description: 'Core network layers or unclassified payloads require manual protocol analysis.',
      icon: HelpCircle,
      accentColor: 'purple',
      packetCount: (classification?.counts.icmp ?? 0) + (classification?.counts.unknown ?? 0) + (classification?.counts.dns ?? 0),
      active: activeTrafficType === 'Unknown Traffic'
    }
  ];

  return (
    <div className="bg-[#0F1623] border border-slate-800 rounded-xl p-5 shadow-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/60 border border-cyan-800/60 text-cyan-300">
              SIH INNOVATION
            </span>
            <h3 className="text-sm font-bold text-white tracking-tight">
              Protocol-Aware Assessment Routing
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Automatic traffic classification and scope routing. Protects against false cryptographic assurance.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400">Current Routing Target:</span>
          <span
            className={`px-2.5 py-1 rounded text-xs font-mono font-bold flex items-center gap-1.5 ${
              isAccepted
                ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                : 'bg-amber-950/60 text-amber-300 border border-amber-800/60'
            }`}
          >
            {isAccepted ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
            <span>{targetEngine}</span>
          </span>
        </div>
      </div>

      {/* Visual Pipeline Routing Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {routes.map((route) => {
          const Icon = route.icon;
          const isActive = route.active;

          return (
            <div
              key={route.id}
              onClick={() => onExploreRoute && onExploreRoute(route.title)}
              className={`p-4 rounded-xl border transition-all flex flex-col justify-between cursor-pointer ${
                isActive
                  ? route.status === 'IN SCOPE'
                    ? 'bg-cyan-950/20 border-cyan-500/80 shadow-[0_0_15px_rgba(6,182,212,0.15)] ring-1 ring-cyan-500/50'
                    : 'bg-amber-950/20 border-amber-500/80 shadow-[0_0_15px_rgba(245,158,11,0.15)] ring-1 ring-amber-500/50'
                  : 'bg-[#0A0E17]/60 border-slate-800/80 hover:border-slate-700 opacity-70 hover:opacity-100'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div
                    className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                      isActive
                        ? route.status === 'IN SCOPE'
                          ? 'bg-cyan-500/20 text-cyan-300'
                          : 'bg-amber-500/20 text-amber-300'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>

                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      route.status === 'IN SCOPE'
                        ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                        : 'bg-amber-950/60 text-amber-300 border border-amber-800/60'
                    }`}
                  >
                    {route.status}
                  </span>
                </div>

                <div className="text-xs font-bold text-white mb-0.5">{route.title}</div>
                <div className="text-[10px] font-mono text-slate-400 mb-2 truncate" title={route.protocols}>
                  {route.protocols}
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed mb-3 line-clamp-2">
                  {route.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-400">Packets:</span>
                <span className={`font-bold tabular-nums ${isActive ? 'text-white' : 'text-slate-400'}`}>
                  {route.packetCount}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Scope Rationale Callout */}
      <div className="mt-3 p-3 bg-[#0A0E17] border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Routing Decision:</span>
          <span className="text-slate-200 font-medium">
            {scopeValidation?.routingDecision.explanation ||
              'Awaiting packet capture classification to determine scope routing.'}
          </span>
        </div>
        <div className="text-[11px] font-mono text-slate-400 shrink-0">
          Evaluator Policy: Zero False Assurance
        </div>
      </div>
    </div>
  );
};
