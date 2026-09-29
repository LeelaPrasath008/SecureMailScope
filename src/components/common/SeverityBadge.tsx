import React from 'react';
import { SeverityLevel, PostureStatus } from '../../types/security';

interface Props {
  severity: SeverityLevel | PostureStatus | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<Props> = ({ severity, size = 'sm' }) => {
  const norm = String(severity).toUpperCase().replace(/\s+/g, '_');

  let bg = 'bg-slate-900';
  let text = 'text-slate-400';
  let border = 'border-slate-700/60';

  if (norm === 'CRITICAL' || norm === 'CRITICAL_RISK') {
    bg = 'bg-rose-950/50';
    text = 'text-rose-400';
    border = 'border-rose-800/70';
  } else if (norm === 'HIGH' || norm === 'HIGH_RISK') {
    bg = 'bg-rose-950/40';
    text = 'text-rose-300';
    border = 'border-rose-800/60';
  } else if (norm === 'MEDIUM' || norm === 'MEDIUM_RISK' || norm === 'AT_RISK') {
    bg = 'bg-amber-950/40';
    text = 'text-amber-400';
    border = 'border-amber-800/60';
  } else if (norm === 'LOW' || norm === 'LOW_RISK') {
    bg = 'bg-cyan-950/40';
    text = 'text-cyan-300';
    border = 'border-cyan-800/50';
  } else if (norm === 'SECURE') {
    bg = 'bg-emerald-950/50';
    text = 'text-emerald-400';
    border = 'border-emerald-800/60';
  } else if (norm === 'OUT_OF_SCOPE') {
    bg = 'bg-amber-950/60';
    text = 'text-amber-300';
    border = 'border-amber-700/70';
  } else if (norm === 'INSUFFICIENT_EVIDENCE' || norm === 'INSUFFICIENT') {
    bg = 'bg-purple-950/60';
    text = 'text-purple-300';
    border = 'border-purple-800/70';
  } else if (norm === 'NOT_ASSESSABLE') {
    bg = 'bg-slate-800/80';
    text = 'text-slate-300';
    border = 'border-slate-700/70';
  }

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs tracking-wide';

  return (
    <span
      className={`inline-flex items-center font-mono font-medium rounded border ${bg} ${text} ${border} ${sizeClasses}`}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-80" />
      {String(severity).replace(/_/g, ' ')}
    </span>
  );
};
